// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI `RawKeyImport` command handler (validation hook, op 2008).
//!
//! Within an open session, import host-supplied **plaintext** key
//! material directly into the partition vault — bypassing the wrap /
//! unwrap path — and return the assigned `key_id` plus a fresh masked-key
//! envelope the host may persist and later re-import.  This is a
//! validation-only hook: it loads Known-Answer-Test key vectors that the
//! normal DDI surface (generate / derive / unwrap) cannot inject.
//!
//! Scope (parity with the legacy firmware `import_raw_key` and its
//! tests): ECDH shared secrets (`Secret256/384/521`), fixed-length HMAC
//! keys (`HmacSha256/384/512`), and variable-length HMAC keys
//! (`VarHmac256/384/512`) import as partition-scoped application keys.
//! `Rsa2kPrivate` imports (usage = `Unwrap` only) as the partition
//! unwrapping key via a dedicated internal-vault path. AES, ECC, and
//! other RSA kinds are
//! rejected with `InvalidKeyType` — those arrive via their own generate
//! / unwrap handlers.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_derive::Ddi;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_ddi_mbor_types::DdiTargetKeyMetadata;
use azihsm_fw_ddi_mbor_types::DdiTargetKeyProperties;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmPartitionManager;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSeedStore;
use azihsm_fw_hsm_pal_traits::HsmVault;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_pal_traits::PartPropId;
use azihsm_fw_uno_drivers_part_store::PartStore;

use super::common::ReqHdr;
use super::common::encode_resp;
use super::common::success_hdr;
use super::get_priv_key::vault_kind_ddi;
use crate::pal::UnoHsmPal;

/// DDI `RawKeyImport` request data.
///
/// The `key_kind` open-enum and the nested `DdiTargetKeyProperties` are
/// the real core wire types: their MBOR codec is generated in the types
/// crate, so composing them into this locally-declared request is
/// byte-identical to `mcr-hsm`'s definition.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiRawKeyImportReq<'a> {
    /// Raw plaintext key material (≤ 3072 bytes).
    #[ddi(id = 1, max_len = 3072)]
    raw: &'a mut DmaBuf,
    /// On-wire key kind the raw bytes are imported as.
    #[ddi(id = 2)]
    key_kind: DdiKeyType,
    /// Optional host key tag (currently rejected).
    #[ddi(id = 3)]
    key_tag: Option<u16>,
    /// Target key properties (usage / availability / label).
    #[ddi(id = 4)]
    key_properties: DdiTargetKeyProperties<'a>,
}

/// DDI `RawKeyImport` response data.
///
/// Mirrors the key-creating handlers: returns the new vault `key_id` and
/// a fresh masked-key envelope the host may persist and later re-import.
/// `bulk_key_id` is reserved for AES bulk variants and is always `None`
/// here.
#[derive(Debug, Ddi)]
#[ddi(map)]
struct DdiRawKeyImportResp<'a> {
    /// ID assigned to the imported key.
    #[ddi(id = 1)]
    key_id: u16,
    /// Fast-path key ID, if applicable.
    #[ddi(id = 2)]
    bulk_key_id: Option<u16>,
    /// Masked key envelope for later re-import.
    #[ddi(id = 3, max_len = 3072)]
    masked_key: &'a [u8],
}

/// Handle `DdiRawKeyImportCmd`.
///
/// The envelope map, header, and data field ID have already been consumed
/// by the caller; `decoder` is positioned at the request data map.
///
/// No `partition_lock` is needed for the application-key path: the only
/// partition-state mutation is the single self-contained
/// `vault_key_create`, with no multi-step read-modify-write held across
/// an await for an interleaved handler to corrupt. The RSA unwrapping-key
/// path accepts only an initial installation and prepares its response
/// before a final synchronous state commit.
///
/// The outer router wipes the complete encoded request after this
/// function returns, including decode failures that occur after the raw
/// plaintext field has been borrowed.
pub(super) async fn dispatch<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    decoder: &mut MborDecoder<'_>,
    request_len: usize,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let mut request =
        DdiRawKeyImportReq::mbor_decode(decoder).map_err(|_| HsmError::DdiDecodeFailed)?;

    let result = if decoder.position() != request_len {
        Err(HsmError::DdiDecodeFailed)
    } else {
        dispatch_request(pal, io, hdr, sess_id, &mut request).await
    };

    // The request DMA allocation is reusable and is not scrubbed
    // automatically. Wipe plaintext on every returning decoded path,
    // including validation and allocation failures.
    request.raw.zeroize();
    result
}

async fn dispatch_request<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    sess_id: u16,
    request: &mut DdiRawKeyImportReq<'_>,
) -> HsmResult<&'p DmaBuf> {
    // Key tags are not supported end to end in the refactor yet:
    // HsmVault::vault_key_create cannot persist a tag, Uno has no tag
    // lookup path, and OpenKey is not implemented. Reject the field
    // rather than accepting and silently discarding it.
    if request.key_tag.is_some() {
        return Err(HsmError::InvalidArg);
    }
    if request.key_properties.key_metadata.session() {
        return Err(HsmError::InvalidArg);
    }

    // RSA-2048 raw import is only valid as the partition unwrapping key
    // (usage = `Unwrap`); it follows a dedicated internal-vault path
    // rather than the generic application-key import below (parity with
    // the legacy `import_raw_key` `Rsa2kPrivate` arm).
    if request.key_kind == DdiKeyType::Rsa2kPrivate {
        return raw_import_unwrapping_key(pal, io, hdr, sess_id, request).await;
    }

    // Restrict the accepted kinds and derive the vault attributes for the
    // imported (non-`local`) key.  Rejects AES / ECC / other RSA kinds
    // (`Rsa2kPrivate` is handled by the unwrapping-key path above) and
    // any usage the kind may not carry.
    let attrs = raw_import_attrs(request.key_kind, &request.key_properties.key_metadata)?;
    let vault_kind = vault_kind_from_ddi(request.key_kind)?;

    // Copy the raw plaintext into a vault-import scratch buffer and
    // commit it as a partition-scoped application key.
    let key_buf = pal.dma_alloc(io, request.raw.len())?;
    key_buf.copy_from_slice(request.raw);
    // The plaintext now lives only in `key_buf`; scrub the host-supplied
    // copy from the request DMA so it does not linger there. `DmaBuf::
    // zeroize` is a volatile, un-elidable wipe.
    request.raw.zeroize();

    let key_handle = pal
        .vault_key_create(io, key_buf, vault_kind, None, attrs)
        .await;

    // Scrub the plaintext scratch before propagating a create failure —
    // per-IO DMA is not implicitly wiped on reuse. `DmaBuf::zeroize` is
    // a volatile, un-elidable wipe.
    key_buf.zeroize();

    let key_handle = key_handle?;
    let key_id: u16 = key_handle.into();

    // Build the host's opaque re-import blob from the committed key so the
    // masked bytes match exactly what the host will later re-import.
    let response = async {
        let plaintext = pal.vault_key(io, key_handle)?;
        let key_length = plaintext.len() as u16;
        let masked_key = mask_blob(
            pal,
            io,
            attrs,
            vault_kind_ddi(vault_kind)?,
            request.key_properties.key_label,
            key_length,
            plaintext,
        )
        .await?;

        pal.dma_alloc_var(io, |buf| {
            encode_resp(
                &success_hdr(hdr, Some(sess_id)),
                &DdiRawKeyImportResp {
                    key_id,
                    bulk_key_id: None,
                    masked_key,
                },
                buf,
            )
        })
    }
    .await;

    match response {
        Ok(response) => Ok(response),
        Err(err) => {
            pal.vault_key_delete(io, key_handle).await?;
            Err(err)
        }
    }
}

/// Import a host-supplied plaintext RSA-2048 private key as the
/// partition **unwrapping key** (validation hook; parity with the legacy
/// `import_raw_key` `Rsa2kPrivate` arm + `import_unwrapping_key`).
///
/// Only `Unwrap` usage is accepted — [`for_rsa_unwrap`] rejects anything
/// else with `InvalidPermissions`. Replacement is rejected until Uno has
/// a real key-retirement mechanism; this avoids zeroizing a key another
/// command may still be reading and avoids leaking an unreferenced vault
/// entry.
///
/// The response carries a masked envelope tagged [`DdiKeyType::RsaUnwrap`]
/// — matching how the unwrapping key is masked elsewhere — so the host's
/// unmask path treats it as the partition unwrapping key rather than a
/// general RSA private key.
async fn raw_import_unwrapping_key<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    hdr: &ReqHdr,
    sess_id: u16,
    request: &mut DdiRawKeyImportReq<'_>,
) -> HsmResult<&'p DmaBuf> {
    // Unwrap-only; SignVerify / EncryptDecrypt -> InvalidPermissions.
    let attrs = for_rsa_unwrap(&request.key_properties.key_metadata)?;
    ensure_unwrapping_key_absent(io)?;

    // Copy the raw plaintext into a vault-import scratch buffer and
    // create an unpublished partition-internal unwrapping key.
    let key_buf = pal.dma_alloc(io, request.raw.len())?;
    key_buf.copy_from_slice(request.raw);
    // The plaintext now lives only in `key_buf`; scrub the host-supplied
    // copy from the request DMA so it does not linger there.
    request.raw.zeroize();

    let key_id = pal
        .vault_key_create(io, key_buf, HsmVaultKeyKind::Rsa2kPrivate, None, attrs)
        .await;

    // Scrub the plaintext scratch before propagating a create failure or
    // updating partition state. `DmaBuf::zeroize` is a volatile,
    // un-elidable wipe.
    key_buf.zeroize();

    let key_id = key_id?;

    // Finish every fallible response operation before changing partition
    // state. If preparation fails, remove the unpublished key and surface
    // the original error; a cleanup failure takes precedence because it
    // means the vault is already inconsistent.
    let resp = match async {
        let plaintext = pal.vault_key(io, key_id)?;
        let key_length = plaintext.len() as u16;
        let masked_key = mask_blob(
            pal,
            io,
            attrs,
            DdiKeyType::RsaUnwrap,
            request.key_properties.key_label,
            key_length,
            plaintext,
        )
        .await?;

        pal.dma_alloc_var(io, |buf| {
            encode_resp(
                &success_hdr(hdr, Some(sess_id)),
                &DdiRawKeyImportResp {
                    key_id: key_id.into(),
                    bulk_key_id: None,
                    masked_key,
                },
                buf,
            )
        })
    }
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            pal.vault_key_delete(io, key_id).await?;
            return Err(e);
        }
    };

    // Recheck after all awaits so two concurrent initial imports cannot
    // both publish. Only the winner becomes visible to other commands.
    if let Err(e) = publish_initial_unwrapping_key(io, key_id) {
        pal.vault_key_delete(io, key_id).await?;
        return Err(e);
    }

    Ok(resp)
}

/// Reject an RSA import when the partition already owns an unwrapping key.
///
/// This reads `PartStore` directly so the check does not trigger the PAL's
/// lazy import of an HSP-staged key.
fn ensure_unwrapping_key_absent(io: &impl HsmIo) -> HsmResult<()> {
    if PartStore::partition(io.pid())?
        .unwrapping_key_id()
        .is_some()
    {
        return Err(HsmError::InvalidArg);
    }
    Ok(())
}

/// Publish the first RSA unwrapping key if the slot is still empty.
fn publish_initial_unwrapping_key(io: &impl HsmIo, key_id: HsmKeyId) -> HsmResult<()> {
    let partition = PartStore::partition(io.pid())?;
    if partition.unwrapping_key_id().is_some() {
        return Err(HsmError::InvalidArg);
    }
    partition.set_unwrapping_key_id(Some(key_id));
    Ok(())
}

/// Build the vault attributes for a raw-imported key, restricting the
/// kind to the two families the legacy firmware allowed.
///
/// Raw-imported keys are host-supplied plaintext, so they are marked
/// **imported** (`local = false`) — the shared usage builders default to
/// `local = true` for on-device provenance, so the flag is forced off
/// here.
fn raw_import_attrs(
    key_kind: DdiKeyType,
    metadata: &DdiTargetKeyMetadata,
) -> HsmResult<HsmVaultKeyAttrs> {
    let attrs = match key_kind {
        DdiKeyType::Secret256 | DdiKeyType::Secret384 | DdiKeyType::Secret521 => {
            for_ecdh_secret(metadata)?
        }
        DdiKeyType::HmacSha256 | DdiKeyType::HmacSha384 | DdiKeyType::HmacSha512 => {
            for_fixed_hmac(metadata)?
        }
        DdiKeyType::VarHmac256 | DdiKeyType::VarHmac384 | DdiKeyType::VarHmac512 => {
            for_var_hmac(metadata)?
        }
        _ => return Err(HsmError::InvalidKeyType),
    };
    Ok(attrs.with_local(false))
}

/// Map an on-wire `DdiKeyType` to the vault kind a raw import creates.
///
/// Mirrors the core `from_ddi::vault_kind_from_ddi`; fixed and variable
/// HMAC wire types map to distinct vault kinds so read-back and masked-key
/// re-import preserve the original key type. Kinds that raw import does
/// not accept return [`HsmError::InvalidKeyType`].
fn vault_kind_from_ddi(key_type: DdiKeyType) -> HsmResult<HsmVaultKeyKind> {
    match key_type {
        DdiKeyType::Secret256 => Ok(HsmVaultKeyKind::Secret256),
        DdiKeyType::Secret384 => Ok(HsmVaultKeyKind::Secret384),
        DdiKeyType::Secret521 => Ok(HsmVaultKeyKind::Secret521),
        DdiKeyType::HmacSha256 => Ok(HsmVaultKeyKind::_HmacSha256),
        DdiKeyType::HmacSha384 => Ok(HsmVaultKeyKind::_HmacSha384),
        DdiKeyType::HmacSha512 => Ok(HsmVaultKeyKind::_HmacSha512),
        DdiKeyType::VarHmac256 => Ok(HsmVaultKeyKind::VarLenHmacSha256),
        DdiKeyType::VarHmac384 => Ok(HsmVaultKeyKind::VarLenHmacSha384),
        DdiKeyType::VarHmac512 => Ok(HsmVaultKeyKind::VarLenHmacSha512),
        _ => Err(HsmError::InvalidKeyType),
    }
}

/// Build vault attrs for a raw-imported ECDH shared secret.
///
/// Derived / imported secrets are HKDF / KBKDF inputs, so the only valid
/// usage is `derive` (PKCS#11 `CKA_DERIVE`).  Any other usage is rejected
/// with [`HsmError::InvalidPermissions`].
fn for_ecdh_secret(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new();

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if !derive {
        return Err(HsmError::InvalidPermissions);
    }
    attrs = attrs.with_derive(true);

    Ok(attrs)
}

/// Build vault attrs for a raw-imported fixed-length HMAC key.
///
/// Fixed-length HMAC keys support only MAC sign / verify usage.
/// Derivation is reserved for variable-length HMAC keys.
fn for_fixed_hmac(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;

    let sign_verify = metadata.sign() && metadata.verify();
    if !sign_verify
        || metadata.encrypt()
        || metadata.decrypt()
        || metadata.derive()
        || metadata.wrap()
        || metadata.unwrap()
    {
        return Err(HsmError::InvalidPermissions);
    }

    Ok(HsmVaultKeyAttrs::new().with_sign(true).with_verify(true))
}

/// Build vault attrs for a raw-imported variable-length HMAC key.
///
/// HMAC keys can sign / verify MACs or act as a key-derivation key
/// (`derive`) for a further KDF.  Exactly one of those two usage groups
/// must be set; `encrypt_decrypt`, `wrap`, and `unwrap` are rejected with
/// [`HsmError::InvalidPermissions`].
fn for_var_hmac(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;
    let mut attrs = HsmVaultKeyAttrs::new();

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    if encrypt_decrypt || wrap || unwrap {
        return Err(HsmError::InvalidPermissions);
    }

    if sign_verify {
        attrs = attrs.with_sign(true).with_verify(true);
    }
    if derive {
        attrs = attrs.with_derive(true);
    }

    Ok(attrs)
}

/// Build vault attrs for a raw-imported RSA-2048 **unwrapping** key.
///
/// Parity with the legacy `import_raw_key` / `import_unwrapping_key`: the
/// partition unwrapping key is a device-internal, device-owned,
/// unwrap-only key.  The only permitted usage is `Unwrap`; any other
/// usage (or none) is rejected with [`HsmError::InvalidPermissions`].
///
/// The returned attrs are identical to the ones a generated unwrapping
/// key carries (`internal + local + unwrap`), so a raw-imported key is
/// indistinguishable from a generated one on read-back.  Unlike the
/// generic raw imports, this path is *not* run through
/// [`raw_import_attrs`]' blanket `with_local(false)` — `local` is
/// intentionally left set.
fn for_rsa_unwrap(metadata: &DdiTargetKeyMetadata) -> HsmResult<HsmVaultKeyAttrs> {
    validate_pairs(metadata)?;

    let sign_verify = metadata.sign() && metadata.verify();
    let encrypt_decrypt = metadata.encrypt() && metadata.decrypt();
    let derive = metadata.derive();
    let wrap = metadata.wrap();
    let unwrap = metadata.unwrap();

    let usage_count = (sign_verify as u8)
        + (encrypt_decrypt as u8)
        + (derive as u8)
        + (wrap as u8)
        + (unwrap as u8);
    if usage_count != 1 || !unwrap {
        return Err(HsmError::InvalidPermissions);
    }

    Ok(HsmVaultKeyAttrs::new()
        .with_internal(true)
        .with_local(true)
        .with_unwrap(true))
}

/// Reject metadata where one half of a paired usage flag is set without
/// the other (`sign` without `verify`, or `encrypt` without `decrypt`).
fn validate_pairs(metadata: &DdiTargetKeyMetadata) -> HsmResult<()> {
    if metadata.sign() != metadata.verify() {
        return Err(HsmError::InvalidPermissions);
    }
    if metadata.encrypt() != metadata.decrypt() {
        return Err(HsmError::InvalidPermissions);
    }
    Ok(())
}

/// Produce a complete masked-key envelope for `plaintext` into a fresh
/// DMA buffer and return the written slice.
///
/// Resolves the partition `MK`, assembles the cleartext metadata,
/// size-queries the envelope, then fills a zeroed scratch buffer.
#[allow(clippy::too_many_arguments)]
async fn mask_blob<'p>(
    pal: &'p UnoHsmPal,
    io: &impl HsmIo,
    attrs: HsmVaultKeyAttrs,
    key_type: DdiKeyType,
    key_label: &[u8],
    key_length: u16,
    plaintext: &[u8],
) -> HsmResult<&'p [u8]> {
    let mk_id = part_mk_key_id(pal, io)?;
    let masking_key = pal.vault_key(io, mk_id)?;

    let bks2_id = u16::try_from(pal.owner_svn()).map_err(|_| HsmError::InvalidArg)?;
    let metadata = DdiMaskedKeyMetadata {
        svn: pal.mfgr_svn(),
        key_type,
        key_attributes: attrs.into(),
        // Always-Some on new masking; Option-typed only for backward
        // compatibility with legacy blobs masked with `None`.
        bks2_index: Some(bks2_id),
        rsvd: None,
        key_label,
        key_length,
    };

    let masked_len = mask(pal, io, masking_key, plaintext, &metadata, None).await?;
    let out = pal.dma_alloc_zeroed(io, masked_len)?;
    mask(pal, io, masking_key, plaintext, &metadata, Some(out)).await?;
    Ok(&out[..masked_len])
}

/// Read the partition masking key (`MK`) id, or fail if the partition
/// has none (a persistent masked blob requested before
/// `EstablishCredential`).
fn part_mk_key_id(pal: &UnoHsmPal, io: &impl HsmIo) -> HsmResult<HsmKeyId> {
    let raw = pal.part_prop_get_u16(io, PartPropId::MK_KEY_ID)?;
    Ok(HsmKeyId::from(raw))
}
