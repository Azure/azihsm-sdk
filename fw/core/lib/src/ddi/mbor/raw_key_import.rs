// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RawKeyImport command handler (test hook, op 2008).
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
//! (`VarHmac256/384/512`) import as session-scoped keys; `Rsa2kPrivate`
//! imports (usage = `Unwrap` only) as the partition unwrapping key via a
//! dedicated internal-vault path. AES, ECC, and other RSA kinds are
//! rejected with `InvalidKeyType` — those arrive via their own generate
//! / unwrap handlers.

use azihsm_fw_ddi_mbor_types::raw_key_import::DdiRawKeyImportReq;
use azihsm_fw_ddi_mbor_types::raw_key_import::DdiRawKeyImportResp;

use super::*;

/// Handle `DdiRawKeyImportCmd`.
///
/// No `partition_lock` is needed: the only partition-state mutation is
/// the single self-contained `vault_key_create`, with no multi-step
/// read-modify-write held across an await for an interleaved handler to
/// corrupt (see [`aes_generate_key`](super::aes_generate_key) for the
/// full rationale).
pub(crate) async fn raw_key_import<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let body: DdiRawKeyImportReq = decoder.decode_data()?;

    // RSA-2048 raw import is only valid as the partition unwrapping key
    // (usage = `Unwrap`); it follows a dedicated internal-vault path
    // rather than the generic session-key import below (parity with the
    // legacy `import_raw_key` `Rsa2kPrivate` arm).
    if body.key_kind == DdiKeyType::Rsa2kPrivate {
        return raw_import_unwrapping_key(pal, io, hdr, sess_id, &body).await;
    }

    // Restrict the accepted kinds and derive the vault attributes for the
    // imported (non-`local`) key.  Rejects AES / ECC / other RSA kinds
    // (`Rsa2kPrivate` is handled by the unwrapping-key path above) and
    // any usage the kind may not carry.
    let attrs = raw_import_attrs(body.key_kind, &body.key_properties.key_metadata)?;
    let vault_kind = super::from_ddi::vault_kind_from_ddi(body.key_kind)?;

    // Session-only keys are anonymous — disallow a host-supplied
    // `key_tag` because the key cannot be looked up across sessions.
    super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;

    // Copy the raw plaintext into a vault-import scratch buffer and
    // commit it, session-scoped iff requested.
    let key_buf = pal.dma_alloc(io, body.raw.len())?;
    key_buf.copy_from_slice(body.raw);

    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
    let key_handle = pal
        .vault_key_create(io, key_buf, vault_kind, session_binding, attrs)
        .await?;
    let key_id: u16 = key_handle.into();

    // Build the host's opaque re-import blob from the committed key so the
    // masked bytes match exactly what the host will later re-import.
    let plaintext = pal.vault_key(io, key_handle)?;
    let masked_key = super::masking::mask_blob(
        pal,
        io,
        HsmSessId::from(sess_id),
        super::masking::MaskSpec {
            attrs,
            key_type: super::from_pal::vault_kind_ddi(vault_kind)?,
            key_label: body.key_properties.key_label,
            key_length: plaintext.len() as u16,
        },
        plaintext,
    )
    .await?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::RawKeyImport, sess_id),
            &DdiRawKeyImportResp {
                key_id,
                bulk_key_id: None,
                masked_key,
            },
            buf,
        )
    })?;

    Ok(resp)
}

/// Import a host-supplied plaintext RSA-2048 private key as the
/// partition **unwrapping key** (test hook; parity with the legacy
/// `import_raw_key` `Rsa2kPrivate` arm + `import_unwrapping_key`).
///
/// Only `Unwrap` usage is accepted — [`for_rsa_unwrap`] rejects
/// anything else with `InvalidPermissions`.  Any existing unwrapping
/// key is deleted first, then the new key is committed to the vault and
/// recorded as the partition unwrapping key id.  The response carries a
/// masked envelope tagged [`DdiKeyType::RsaUnwrap`] — matching how
/// [`get_unwrapping_key`](super::get_unwrapping_key) masks it — so the
/// host's unmask path treats it as the partition unwrapping key rather
/// than a general RSA private key.
///
/// [`for_rsa_unwrap`]: super::key_attrs::for_rsa_unwrap
async fn raw_import_unwrapping_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    hdr: &DdiReqHdr,
    sess_id: u16,
    body: &DdiRawKeyImportReq<'_>,
) -> HsmResult<&'p DmaBuf> {
    // Unwrap-only; SignVerify / EncryptDecrypt -> InvalidPermissions.
    let attrs = super::key_attrs::for_rsa_unwrap(&body.key_properties.key_metadata)?;

    // Replace any existing partition unwrapping key before importing the
    // new one (parity with the legacy delete-then-import sequence).
    if let Ok(old_id) = crate::part_state::part_unwrapping_key_id(pal, io) {
        pal.vault_key_delete(io, old_id).await?;
    }

    // Copy the raw plaintext into a vault-import scratch buffer and
    // commit it as the partition-internal unwrapping key.
    let key_buf = pal.dma_alloc(io, body.raw.len())?;
    key_buf.copy_from_slice(body.raw);

    let key_id = pal
        .vault_key_create(io, key_buf, HsmVaultKeyKind::Rsa2kPrivate, None, attrs)
        .await?;
    crate::part_state::part_set_unwrapping_key_id(pal, io, key_id)?;

    // Build the host's opaque re-import blob from the committed key,
    // tagged as the partition unwrapping key.
    let plaintext = pal.vault_key(io, key_id)?;
    let masked_key = super::masking::mask_blob(
        pal,
        io,
        HsmSessId::from(sess_id),
        super::masking::MaskSpec {
            attrs,
            key_type: DdiKeyType::RsaUnwrap,
            key_label: body.key_properties.key_label,
            key_length: plaintext.len() as u16,
        },
        plaintext,
    )
    .await?;

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::RawKeyImport, sess_id),
            &DdiRawKeyImportResp {
                key_id: key_id.into(),
                bulk_key_id: None,
                masked_key,
            },
            buf,
        )
    })?;

    Ok(resp)
}

/// Build the vault attributes for a raw-imported key, restricting the
/// kind to the two families the legacy firmware allowed.
///
/// Raw-imported keys are host-supplied plaintext, so they are marked
/// **imported** (`local = false`) — the shared derive-key builders
/// default to `local = true` for on-device derivation, so the flag is
/// forced off here.
fn raw_import_attrs(
    key_kind: DdiKeyType,
    metadata: &DdiTargetKeyMetadata,
) -> HsmResult<HsmVaultKeyAttrs> {
    let attrs = match key_kind {
        DdiKeyType::Secret256 | DdiKeyType::Secret384 | DdiKeyType::Secret521 => {
            super::key_attrs::for_ecdh_secret(metadata)?
        }
        DdiKeyType::HmacSha256
        | DdiKeyType::HmacSha384
        | DdiKeyType::HmacSha512
        | DdiKeyType::VarHmac256
        | DdiKeyType::VarHmac384
        | DdiKeyType::VarHmac512 => super::key_attrs::for_var_hmac(metadata)?,
        _ => return Err(HsmError::InvalidKeyType),
    };
    Ok(attrs.with_local(false))
}
