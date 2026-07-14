// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI RsaUnwrap command handler.
//!
//! Implements the firmware side of `CKM_RSA_AES_KEY_WRAP`: within an
//! open session, unwrap a host-supplied key blob with the partition's
//! RSA-2048 *unwrapping* key (see
//! [`GetUnwrappingKey`](super::DdiOp::GetUnwrappingKey)) and import the
//! recovered key into the vault.
//!
//! This handler is deliberately thin: the unwrap + key-classification
//! mechanics live in the protocol-neutral [`azihsm_fw_hsm_key_unwrap`]
//! crate so the same implementation can back a future TBOR handler.  The
//! handler owns the MBOR-specific concerns and the vault persistence:
//!   1. decode the request and validate the OAEP padding / hash,
//!   2. derive the imported key's vault attributes from the wire key
//!      properties (and validate any key tag),
//!   3. create the vault key from the recovered material, and
//!   4. frame the [`DdiRsaUnwrapResp`].
//!
//! The recovered key is enveloped into the response's `masked_key` slot
//! **in place** — the AES-CBC-256 + HMAC-SHA-384 envelope is written
//! straight into the reserved response region (no scratch buffer, no
//! copy), matching the zero-copy `reserve` / `from_layout` pattern used
//! by the other key-producing handlers and the reference firmware.  This
//! keeps the largest RSA-4096 keys within the fixed per-IO DMA budget.
//! The AES, RSA (plain / CRT), and ECC key classes are wired; the AES
//! bulk variants are not yet supported.  RSA and ECC imports return the
//! imported key's wire public key, re-derived from the committed vault
//! key.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapReq;
use azihsm_fw_ddi_mbor_types::rsa_unwrap::DdiRsaUnwrapResp;
use azihsm_fw_ddi_mbor_types::DdiKeyClass;
use azihsm_fw_ddi_mbor_types::DdiPublicKey;
use azihsm_fw_ddi_mbor_types::DdiRsaCryptoPadding;
use azihsm_fw_hsm_key_decode::decode;
use azihsm_fw_hsm_key_decode::KeyClass;
use azihsm_fw_hsm_key_unwrap::unwrap_key;
use azihsm_fw_hsm_key_unwrap::UnwrapParams;
use azihsm_fw_hsm_pal_traits::HsmSessId;

use super::*;

/// Handle `DdiRsaUnwrapCmd`.
pub(crate) async fn rsa_unwrap<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiRsaUnwrapReq = decoder.decode_data()?;
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Only RSA-OAEP wrapping is supported.
    if body.wrapped_blob_padding != DdiRsaCryptoPadding::Oaep {
        return Err(HsmError::InvalidArg);
    }
    let oaep_hash = super::from_ddi::hash(body.wrapped_blob_hash_algorithm)?;

    // The request `key_id` must name the partition's RSA-2048 unwrapping
    // key.  Rather than re-resolve the `part_unwrapping_key_id` property
    // and match it here, the engine below validates the key directly
    // against the vault, which is both sufficient and strictly tighter:
    //
    //   * A stale / incorrect id cannot slip through.  The engine requires
    //     an `internal` `Rsa2kPrivate` that carries the `unwrap`
    //     permission.  `internal` is set *only* by the device when it
    //     provisions the unwrapping key — no host-facing key-attr builder
    //     ever sets it, and `for_rsa` refuses the `unwrap` usage outright —
    //     so no host-imported key can satisfy these checks.  The partition
    //     unwrapping key is therefore the only key that passes; a wrong id
    //     fails with `KeyNotFound` (absent), `RsaUnwrapInvalidRequest`
    //     (wrong kind / not internal), or `InvalidPermissions` (no unwrap).
    //   * A still-pending key is not reachable here.  RsaUnwrap runs only
    //     inside an open session, and the host must first call
    //     `GetUnwrappingKey` — which resolves the property and awaits
    //     generation, surfacing `PendingKeyGeneration` — to obtain the
    //     public key it wraps this blob against; by then the key is
    //     generated and present in the vault.
    //
    // This mirrors the reference firmware, which looks the key up by request
    // id (in its internal-keys vault, requiring `Unwrap` usage) with no
    // separate property comparison.
    let unwrap_key_id = HsmKeyId::from(body.key_id);

    // Map the wire key class to the neutral import class and derive the
    // imported key's vault attributes.  These keys are imported, not
    // generated on-device, so the `for_*` builders are told `local = false`
    // (and, as always, never set `internal`).  AES, RSA (plain / CRT), and
    // ECC are supported; the AES bulk variants are not yet wired.
    let (key_class, import_attrs) = match body.wrapped_blob_key_class {
        DdiKeyClass::Aes => {
            let attrs = super::key_attrs::for_aes(&body.key_properties.key_metadata, false)?;
            super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;
            (KeyClass::Aes, attrs)
        }
        DdiKeyClass::Rsa | DdiKeyClass::RsaCrt => {
            let attrs = super::key_attrs::for_rsa(&body.key_properties.key_metadata, false)?;
            super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;
            let class = match body.wrapped_blob_key_class {
                DdiKeyClass::RsaCrt => KeyClass::RsaCrt,
                _ => KeyClass::Rsa,
            };
            (class, attrs)
        }
        DdiKeyClass::Ecc => {
            let attrs = super::key_attrs::for_ecc(&body.key_properties.key_metadata, false)?;
            super::key_attrs::check_session_key_tag(attrs, body.key_tag)?;
            (KeyClass::Ecc, attrs)
        }
        _ => return Err(HsmError::UnsupportedCmd),
    };

    // Durable stash for the imported key's re-derived public bytes,
    // allocated before the response frame; the framing below copies it
    // into the response's `pub_key` slot.  RSA `n_le ‖ e_le`, ECC `x ‖ y`;
    // AES has none.  The unwrap/decode scratch is freed first (below), so
    // only this small stash plus the response share the arena with the
    // request — well within the per-IO DMA budget even for RSA-4096-CRT.
    //
    // Run OAEP-decrypt, KWP-unwrap, decode, and vault import inside an
    // allocation scope so the large scratch (multi-KB for RSA) is freed
    // before the response is built.  The committed vault key outlives the
    // scope; only its (owned) id and kind escape.  The public key is *not*
    // ferried out — it is re-derived from the committed vault key below,
    // so no large public bytes cross the scope.
    let (key_id, vault_kind) = pal
        .alloc_scoped_async(
            io,
            async |_scope| -> HsmResult<(HsmKeyId, HsmVaultKeyKind)> {
                // Unwrap the blob (crypto only): OAEP-decrypt the KEK and
                // AES-KWP unwrap the payload → raw recovered key material.
                let material = unwrap_key(
                    pal,
                    io,
                    UnwrapParams {
                        unwrap_key_id,
                        oaep_hash,
                        wrapped_blob: &*body.wrapped_blob,
                    },
                )
                .await?;

                // Decode the recovered material into vault-ready form.
                let decoded = decode(pal, io, material, key_class).await?;
                let vault_kind = decoded.kind;

                // Persist the decoded key, session-bound iff its attrs ask.
                let session_binding = import_attrs.session().then_some(HsmSessId::from(sess_id));
                let key_id = pal
                    .vault_key_create(
                        io,
                        decoded.material,
                        vault_kind,
                        session_binding,
                        import_attrs,
                    )
                    .await?;

                Ok((key_id, vault_kind))
            },
        )
        .await?;

    // The unwrap/import scratch is now freed.  Read the committed key back
    // (from vault storage, not the per-IO arena) to drive both the
    // public-key re-derivation and the masked envelope.
    let attrs = pal.vault_key_attrs(io, key_id)?;
    let priv_blob = pal.vault_key(io, key_id)?;

    // Re-derive the wire public key for the asymmetric classes into a
    // small exact-length stash; AES has none.  Re-deriving from the
    // committed private key (rather than trusting decoded bytes) mirrors
    // the unmask path and the reference firmware.
    let pub_key = match pub_wire_spec(vault_kind) {
        Some((is_rsa, pub_kind)) => {
            let pub_len = if is_rsa {
                pal.rsa_priv_pub_key(io, priv_blob, None)?
            } else {
                pal.ecc_priv_pub_key(io, priv_blob, None).await?
            };
            let pub_buf = pal.dma_alloc(io, pub_len)?;
            if is_rsa {
                pal.rsa_priv_pub_key(io, priv_blob, Some(pub_buf))?;
            } else {
                pal.ecc_priv_pub_key(io, priv_blob, Some(pub_buf)).await?;
            }
            Some(DdiPublicKey {
                raw: pub_buf,
                key_kind: pub_kind,
            })
        }
        None => None,
    };

    // Resolve the masking key + metadata and query the envelope length so
    // the response's `masked_key` region can be reserved to fit exactly.
    let masking_key =
        super::masking::resolve_masking_key(pal, io, HsmSessId::from(sess_id), attrs.session())?;
    let metadata = super::masking::masked_metadata(
        pal,
        super::from_pal::vault_kind_ddi(vault_kind)?,
        attrs,
        body.key_properties.key_label,
        priv_blob.len() as u16,
    )?;
    let masked_len = mask(pal, io, masking_key, priv_blob, &metadata, None).await?;

    // Frame the response — reserving the `pub_key` (copied) and `masked_key`
    // (in place) regions — then envelope the private material directly into
    // the reserved `masked_key` slot: no separate buffer, no copy.
    let kind = ddi_key_type(vault_kind)?;
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::RsaUnwrap, sess_id),
            buf,
        )?;
        let layout = DdiRsaUnwrapResp::reserve(
            &mut encoder,
            u16::from(key_id),
            pub_key,
            None,
            kind,
            masked_len,
        )?;
        Ok((encoder.position(), layout))
    })?;

    // `mask` requires `out[..total_len]` zeroed on entry; the encoder does
    // not zero the reserved slot, so clear it before filling.
    let frame = DdiRsaUnwrapResp::from_layout(resp, &layout);
    frame.masked_key.fill(0);
    mask(
        pal,
        io,
        masking_key,
        priv_blob,
        &metadata,
        Some(frame.masked_key),
    )
    .await?;

    Ok(resp)
}

/// Map an imported vault key kind to its DDI wire key type.
///
/// Covers the AES, RSA (plain / CRT), and ECC private kinds the handler
/// can produce; an unexpected kind here is an internal invariant break.
fn ddi_key_type(kind: HsmVaultKeyKind) -> HsmResult<DdiKeyType> {
    match kind {
        HsmVaultKeyKind::Aes128 => Ok(DdiKeyType::Aes128),
        HsmVaultKeyKind::Aes192 => Ok(DdiKeyType::Aes192),
        HsmVaultKeyKind::Aes256 => Ok(DdiKeyType::Aes256),
        HsmVaultKeyKind::Rsa2kPrivate => Ok(DdiKeyType::Rsa2kPrivate),
        HsmVaultKeyKind::Rsa3kPrivate => Ok(DdiKeyType::Rsa3kPrivate),
        HsmVaultKeyKind::Rsa4kPrivate => Ok(DdiKeyType::Rsa4kPrivate),
        HsmVaultKeyKind::Rsa2kPrivateCrt => Ok(DdiKeyType::Rsa2kPrivateCrt),
        HsmVaultKeyKind::Rsa3kPrivateCrt => Ok(DdiKeyType::Rsa3kPrivateCrt),
        HsmVaultKeyKind::Rsa4kPrivateCrt => Ok(DdiKeyType::Rsa4kPrivateCrt),
        HsmVaultKeyKind::Ecc256Private => Ok(DdiKeyType::Ecc256Private),
        HsmVaultKeyKind::Ecc384Private => Ok(DdiKeyType::Ecc384Private),
        HsmVaultKeyKind::Ecc521Private => Ok(DdiKeyType::Ecc521Private),
        _ => Err(HsmError::InternalError),
    }
}

/// Map an imported asymmetric private key kind to `(is_rsa, wire public
/// key type)` for re-deriving and framing the response `pub_key`.  Only
/// RSA / ECC private kinds carry a public key here; AES (and any other
/// kind) returns `None`.
fn pub_wire_spec(kind: HsmVaultKeyKind) -> Option<(bool, DdiKeyType)> {
    match kind {
        HsmVaultKeyKind::Rsa2kPrivate | HsmVaultKeyKind::Rsa2kPrivateCrt => {
            Some((true, DdiKeyType::Rsa2kPublic))
        }
        HsmVaultKeyKind::Rsa3kPrivate | HsmVaultKeyKind::Rsa3kPrivateCrt => {
            Some((true, DdiKeyType::Rsa3kPublic))
        }
        HsmVaultKeyKind::Rsa4kPrivate | HsmVaultKeyKind::Rsa4kPrivateCrt => {
            Some((true, DdiKeyType::Rsa4kPublic))
        }
        HsmVaultKeyKind::Ecc256Private => Some((false, DdiKeyType::Ecc256Public)),
        HsmVaultKeyKind::Ecc384Private => Some((false, DdiKeyType::Ecc384Public)),
        HsmVaultKeyKind::Ecc521Private => Some((false, DdiKeyType::Ecc521Public)),
        _ => None,
    }
}
