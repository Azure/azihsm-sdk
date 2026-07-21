// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `UnwrapKey` command handler.
//!
//! Implements `CKM_RSA_AES_KEY_WRAP` for the TBOR transport: within an open
//! session, unwrap a host-supplied wrapped-key blob with the partition's
//! RSA-2048 unwrapping key and return the recovered key as a **masked**
//! blob under the requested scope's masking key — the TBOR analogue of
//! MBOR `RsaUnwrap`, but re-masking the recovered key instead of vaulting
//! it.
//!
//! The unwrap + key-classification mechanics live in the protocol-neutral
//! [`azihsm_fw_hsm_key_unwrap`] / [`azihsm_fw_hsm_key_decode`] crates
//! (shared with MBOR `RsaUnwrap`).  This handler owns the TBOR concerns:
//! resolve the internal unwrapping key, decode the recovered material, mask
//! it under the scope, and — for the RSA / ECC classes — return the
//! re-derived wire public key.  Available to both Crypto-Officer and
//! Crypto-User sessions.

use azihsm_fw_core_crypto_key_masking::aead::mask;
use azihsm_fw_core_crypto_key_masking::aead::masked_blob_len;
use azihsm_fw_core_crypto_key_masking::aead::AeadAlg;
use azihsm_fw_core_crypto_key_masking::aead::MaskParams;
use azihsm_fw_ddi_tbor_types::HashAlgo;
use azihsm_fw_ddi_tbor_types::KeyClass;
use azihsm_fw_ddi_tbor_types::KeyUsage;
use azihsm_fw_ddi_tbor_types::TborUnwrapKeyReq;
use azihsm_fw_ddi_tbor_types::TborUnwrapKeyResp;
use azihsm_fw_ddi_tbor_types::UNWRAP_MASKED_KEY_MAX_LEN;
use azihsm_fw_ddi_tbor_types::UNWRAP_PUB_KEY_MAX_LEN;
use azihsm_fw_hsm_key_decode::decode;
use azihsm_fw_hsm_key_decode::KeyClass as DecodeKeyClass;
use azihsm_fw_hsm_key_unwrap::unwrap_key;
use azihsm_fw_hsm_key_unwrap::UnwrapParams;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmKeyId;
use azihsm_fw_hsm_pal_traits::HsmKeyScope;
use azihsm_fw_hsm_pal_traits::HsmPal;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmScopedAlloc;
use azihsm_fw_hsm_pal_traits::HsmSessId;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use azihsm_fw_hsm_undo::UndoLog;

use super::resolve_masking_key;
use super::validate_active_session;
use crate::part_state;

/// Envelope key-label recorded in the masked blob's `MaskedKeyMetadata`.
const UNWRAP_KEY_LABEL: &[u8] = b"UnwrappedKey";

/// Map the wire OAEP [`HashAlgo`] onto the firmware hash algorithm.
fn oaep_hsm_hash(algo: HashAlgo) -> HsmResult<HsmHashAlgo> {
    match algo {
        HashAlgo::Sha256 => Ok(HsmHashAlgo::Sha256),
        HashAlgo::Sha384 => Ok(HsmHashAlgo::Sha384),
        HashAlgo::Sha512 => Ok(HsmHashAlgo::Sha512),
        _ => Err(HsmError::InvalidArg),
    }
}

/// Map the wire [`KeyClass`] onto the decode crate's key class.
fn decode_class(class: KeyClass) -> HsmResult<DecodeKeyClass> {
    match class {
        KeyClass::Aes => Ok(DecodeKeyClass::Aes),
        KeyClass::Rsa => Ok(DecodeKeyClass::Rsa),
        KeyClass::RsaCrt => Ok(DecodeKeyClass::RsaCrt),
        KeyClass::Ecc => Ok(DecodeKeyClass::Ecc),
        KeyClass::HmacSha256 => Ok(DecodeKeyClass::HmacSha256),
        KeyClass::HmacSha384 => Ok(DecodeKeyClass::HmacSha384),
        KeyClass::HmacSha512 => Ok(DecodeKeyClass::HmacSha512),
        _ => Err(HsmError::UnsupportedCmd),
    }
}

/// Derive the vault usage attributes for an imported key of `class` from
/// the host-requested [`KeyUsage`] permissions, plus the requested
/// `scope`.  Imported keys are never `local`.
///
/// Mirrors the MBOR `key_attrs::for_*` policy: `sign`+`verify` and
/// `encrypt`+`decrypt` are matched pairs, exactly one usage group may be
/// set, and each key class restricts which group(s) are valid:
/// - AES → `encrypt`+`decrypt` only;
/// - RSA → `sign`+`verify` or `encrypt`+`decrypt`;
/// - ECC → `sign`+`verify` or `derive`;
/// - HMAC → `sign`+`verify`.
///
/// Any invalid pairing, multi-usage request, or usage not permitted for
/// the class is rejected with [`HsmError::InvalidPermissions`].
fn attrs_for_class(
    class: KeyClass,
    scope: HsmKeyScope,
    usage: KeyUsage,
) -> HsmResult<HsmVaultKeyAttrs> {
    // Paired usages must be requested together.
    if usage.sign() != usage.verify() || usage.encrypt() != usage.decrypt() {
        return Err(HsmError::InvalidPermissions);
    }

    let sign_verify = usage.sign() && usage.verify();
    let encrypt_decrypt = usage.encrypt() && usage.decrypt();
    let derive = usage.derive();
    let wrap = usage.wrap();
    let unwrap = usage.unwrap();

    // Exactly one usage group may be set.
    let usage_count =
        sign_verify as u8 + encrypt_decrypt as u8 + derive as u8 + wrap as u8 + unwrap as u8;
    if usage_count != 1 {
        return Err(HsmError::InvalidPermissions);
    }

    let base = HsmVaultKeyAttrs::new().with_scope(scope);
    let attrs = match class {
        // Symmetric cipher key: encrypt / decrypt only.
        KeyClass::Aes if encrypt_decrypt => base.with_encrypt(true).with_decrypt(true),
        // RSA private key: sign / verify or encrypt / decrypt.
        KeyClass::Rsa | KeyClass::RsaCrt if sign_verify => base.with_sign(true).with_verify(true),
        KeyClass::Rsa | KeyClass::RsaCrt if encrypt_decrypt => {
            base.with_encrypt(true).with_decrypt(true)
        }
        // ECC private key: sign / verify or derive (ECDH).
        KeyClass::Ecc if sign_verify => base.with_sign(true).with_verify(true),
        KeyClass::Ecc if derive => base.with_derive(true),
        // HMAC key: sign / verify (MAC compute / verify).
        KeyClass::HmacSha256 | KeyClass::HmacSha384 | KeyClass::HmacSha512 if sign_verify => {
            base.with_sign(true).with_verify(true)
        }
        // Any recognized class with a usage it does not permit.
        KeyClass::Aes
        | KeyClass::Rsa
        | KeyClass::RsaCrt
        | KeyClass::Ecc
        | KeyClass::HmacSha256
        | KeyClass::HmacSha384
        | KeyClass::HmacSha512 => return Err(HsmError::InvalidPermissions),
        // Unrecognized class discriminant.
        _ => return Err(HsmError::UnsupportedCmd),
    };
    Ok(attrs)
}

/// Which wire public key (if any) an imported private key kind carries,
/// and how to re-derive it from the vault-resident private key.
enum PubDeriv {
    /// RSA — wire public key is `n_le ‖ e_le`, via `rsa_priv_pub_key`.
    Rsa,
    /// ECC — wire public key is `x ‖ y`, via `ecc_priv_pub_key`.
    Ecc,
}

/// Classify an imported vault key kind for public-key re-derivation.
/// Symmetric kinds (AES / HMAC) carry no public key → `None`.
fn pub_deriv(kind: HsmVaultKeyKind) -> Option<PubDeriv> {
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate
        | HsmVaultKeyKind::Rsa3kPrivate
        | HsmVaultKeyKind::Rsa4kPrivate
        | HsmVaultKeyKind::Rsa2kPrivateCrt
        | HsmVaultKeyKind::Rsa3kPrivateCrt
        | HsmVaultKeyKind::Rsa4kPrivateCrt => Some(PubDeriv::Rsa),
        HsmVaultKeyKind::Ecc256Private
        | HsmVaultKeyKind::Ecc384Private
        | HsmVaultKeyKind::Ecc521Private => Some(PubDeriv::Ecc),
        _ => None,
    }
}

/// Masking context for the recovered key — everything `mask` needs beyond
/// the key material itself, resolved once in [`handle`] and threaded into
/// [`encode_and_mask`].
struct MaskCtx {
    /// Scope whose masking key wraps the recovered key.
    scope: HsmKeyScope,
    /// Session the request is bound to (resolves the `Session`-scope key).
    sess_id: HsmSessId,
    /// Partition SVN bound into the masked blob (anti-rollback).
    svn: u64,
    /// Owner-seed lineage id bound into the masked blob.
    owner: u16,
    /// Usage attributes recorded in the masked blob's metadata.
    attrs: HsmVaultKeyAttrs,
}

/// Handle a TBOR `UnwrapKey` request.
///
/// **DMA budget:** the recovered key is vaulted **transiently** — created
/// inside an allocation scope (so the multi-KB unwrap / decode scratch is
/// freed before the response is built), masked from vault storage (which
/// lives outside the per-IO DMA arena), then deleted.  This mirrors MBOR
/// `RsaUnwrap`, whose vault step is what keeps the largest RSA-4096 keys
/// within the fixed per-IO DMA budget; masking the material straight from
/// the arena instead would require the material and the masked output to
/// coexist, overrunning the budget for RSA-3072 / 4096.
///
/// **Cleanup:** the transient key is registered in the undo log
/// (`push_vault_create`) immediately after creation, so any failure before
/// the explicit delete is rolled back (undo → delete).  On success the key
/// is deleted explicitly and the undo log discarded — TBOR persists
/// nothing.
pub(crate) async fn handle<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    req_buf: &DmaBuf,
    undo: &mut UndoLog<'p>,
) -> HsmResult<&'p DmaBuf> {
    let req = TborUnwrapKeyReq::decode(req_buf)?;
    let sess_id = HsmSessId::from(u16::from(req.session_id()));
    let scope = HsmKeyScope(req.scope().0);
    validate_active_session(pal, io, sess_id)?;

    let oaep_hash_algo = oaep_hsm_hash(req.oaep_hash_algo())?;
    let class = req.key_class();
    let dclass = decode_class(class)?;
    let wrapped_blob = req.wrapped_blob();

    // Resolve the partition's RSA-2048 unwrapping key id; an absent id means
    // generation is still pending, surfaced so the host retries (call
    // `GetUnwrappingKey` first).
    let unwrap_key_id = match part_state::part_unwrapping_key_id(pal, io) {
        Ok(id) => id,
        Err(HsmError::PartPropNotFound) => return Err(HsmError::PendingKeyGeneration),
        Err(e) => return Err(e),
    };

    // Platform identity bound into the masked blob (anti-rollback on
    // re-import).
    let svn = part_state::part_mfgr_svn(pal);
    let owner = u16::try_from(part_state::part_owner_svn(pal)).map_err(|_| HsmError::InvalidArg)?;
    let attrs = attrs_for_class(class, scope, req.key_usage())?;

    // Phase 1 — unwrap, decode, and vault the recovered key inside an
    // allocation scope.  The (multi-KB, for RSA) unwrap / decode scratch is
    // freed when the scope exits; the key survives in vault storage (outside
    // the per-IO DMA arena) and is read back below.
    let key_id = pal
        .alloc_scoped_async(io, async |_scope| -> HsmResult<HsmKeyId> {
            let material = unwrap_key(
                pal,
                io,
                UnwrapParams {
                    unwrap_key_id,
                    oaep_hash: oaep_hash_algo,
                    wrapped_blob,
                },
            )
            .await?;
            // Decode + import into the transient vault inside a nested block
            // so the `decoded` borrow of `material` ends before the wipe;
            // then scrub the recovered plaintext from the DMA arena on every
            // path — scope exit only resets the bump watermark, it does not
            // wipe freed memory.
            let created = async {
                let decoded = decode(pal, io, &mut *material, dclass).await?;
                // Transient, partition-scoped (`None` session): deleted below.
                pal.vault_key_create(io, decoded.material, decoded.kind, None, attrs)
                    .await
            }
            .await;
            material.zeroize();
            created
        })
        .await?;

    // Register the transient key so a failure before the explicit delete
    // still cleans it up (undo walk → delete).  If the log is full the key
    // is already vaulted but unregistered, so delete it here rather than
    // leaking a persisted key holding sensitive material.
    if let Err(e) = undo.push_vault_create(key_id) {
        let _ = pal.vault_key_delete(io, key_id).await;
        return Err(e);
    }

    // Phase 2 — mask the vault-resident key into the response, then delete
    // the transient key.  On any error the key is left for the undo walk to
    // delete; on success we delete it here and discard the log.
    let mask_ctx = MaskCtx {
        scope,
        sess_id,
        svn,
        owner,
        attrs,
    };
    match encode_and_mask(pal, io, key_id, &mask_ctx).await {
        Ok(resp) => {
            pal.vault_key_delete(io, key_id).await?;
            undo.discard();
            Ok(resp)
        }
        Err(e) => Err(e),
    }
}

/// Build the `UnwrapKey` response around the vault-resident recovered key:
/// reserve the `masked_key` and `pub_key` slots, derive the wire public key
/// (RSA / ECC) straight into its slot, and mask the private key straight
/// into its slot — no scratch buffers, no copies.
async fn encode_and_mask<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    key_id: HsmKeyId,
    ctx: &MaskCtx,
) -> HsmResult<&'p DmaBuf> {
    let kind = pal.vault_key_kind(io, key_id)?;
    let priv_blob = pal.vault_key(io, key_id)?;

    // Size the masked blob and the wire public key up front so both response
    // slots can be reserved to exactly fit.
    let masked_len = masked_blob_len(AeadAlg::AesGcm256, priv_blob.len());
    if masked_len > UNWRAP_MASKED_KEY_MAX_LEN {
        return Err(HsmError::InternalError);
    }
    let deriv = pub_deriv(kind);
    let pub_len = match deriv {
        Some(PubDeriv::Rsa) => pal.rsa_priv_pub_key(io, priv_blob, None)?,
        Some(PubDeriv::Ecc) => pal.ecc_priv_pub_key(io, priv_blob, None).await?,
        None => 0,
    };
    if pub_len > UNWRAP_PUB_KEY_MAX_LEN {
        return Err(HsmError::InternalError);
    }

    // Build the response with both data slots reserved (sized exactly).
    let resp = pal.dma_alloc_var(io, |buf| {
        let frame = TborUnwrapKeyResp::encode(buf, 0, false)?
            .key_kind(kind.0)?
            .masked_key_reserve(masked_len)?
            .pub_key_reserve(pub_len)?
            .finish();
        Ok(frame.as_bytes().len())
    })?;

    // Fill both slots in place: derive the public key into its slot, then
    // mask the private key into its slot (mask's IV / AAD / label scratch is
    // scoped and freed on return).
    {
        let out = TborUnwrapKeyResp::decode_mut(resp)?;
        match deriv {
            Some(PubDeriv::Rsa) => {
                if pal.rsa_priv_pub_key(io, priv_blob, Some(out.pub_key))? != pub_len {
                    return Err(HsmError::InternalError);
                }
            }
            Some(PubDeriv::Ecc) => {
                if pal
                    .ecc_priv_pub_key(io, priv_blob, Some(out.pub_key))
                    .await?
                    != pub_len
                {
                    return Err(HsmError::InternalError);
                }
            }
            None => {}
        }
        pal.alloc_scoped_async(io, async |alloc| -> HsmResult<()> {
            let masking_key = resolve_masking_key(pal, io, ctx.scope, ctx.sess_id)?;
            let key_label = alloc.dma_alloc(UNWRAP_KEY_LABEL.len())?;
            key_label.copy_from_slice(UNWRAP_KEY_LABEL);
            let params = MaskParams {
                key_kind: kind,
                key_attrs: ctx.attrs,
                svn: ctx.svn,
                owner_seed_id: ctx.owner,
                key_label,
            };
            let written = mask(
                pal,
                io,
                alloc,
                AeadAlg::AesGcm256,
                masking_key,
                &params,
                priv_blob,
                Some(out.masked_key),
            )
            .await?;
            // `mask` leaves any trailing bytes of the reserved slot
            // untouched; the slot was reserved to exactly `masked_len`, so a
            // short write would leave uninitialized bytes in the response.
            if written != masked_len {
                return Err(HsmError::InternalError);
            }
            Ok(())
        })
        .await?;
    }

    Ok(resp)
}
