// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI UnmaskKey command handler.
//!
//! Inverse of the masking (return) side ([`masking`](super::masking)):
//! recover a host-held masked-key blob and re-import the key into the
//! partition vault, returning the new vault key id.
//!
//! The blob is an AES-CBC-256 + HMAC-SHA-384 envelope.  Its scope is read
//! from the cleartext (MAC-covered) metadata to select the masking key —
//! the per-session masking key for session-scoped keys, the partition
//! masking key (`MK`) otherwise.  Reading the scope before authenticating
//! is safe: a tampered scope selects the wrong key, and because [`unmask`]
//! verifies the HMAC before decrypting, the mismatch is rejected without
//! touching the ciphertext.
//!
//! The response carries a **fresh** masked-key envelope of the re-imported
//! key — the key re-masked under the current scope's masking key, recording
//! the current SVN, but preserving the original key type, attributes, and
//! label.  The input blob is not echoed back: its masking key / SVN may
//! have rolled since it was produced, so the host persists this fresh
//! envelope to keep the key re-importable.  Like the other key-producing
//! handlers, the envelope is written in place into the reserved response
//! slot to stay within the per-IO DMA budget.

use azihsm_fw_core_crypto_key_masking::cbc::mask;
use azihsm_fw_core_crypto_key_masking::cbc::peek_metadata;
use azihsm_fw_core_crypto_key_masking::cbc::unmask;
use azihsm_fw_ddi_mbor::MborDecode;
use azihsm_fw_ddi_mbor::MborDecoder;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_ddi_mbor_types::unmask_key::DdiUnmaskKeyReq;
use azihsm_fw_ddi_mbor_types::unmask_key::DdiUnmaskKeyResp;
use azihsm_fw_ddi_mbor_types::DdiKeyType;
use azihsm_fw_ddi_mbor_types::DdiPublicKey;

use super::*;

/// Handle `DdiUnmaskKeyCmd`.
pub(crate) async fn unmask_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;
    let body: DdiUnmaskKeyReq = decoder.decode_data()?;

    // Decode the blob's cleartext (MAC-covered) metadata WITHOUT the
    // masking key: its recorded scope selects which masking key the blob
    // was enveloped under, and its `key_type` / length drive the
    // re-import.  These values are only *acted on* after `unmask` (below)
    // verifies the HMAC; the peek trusts nothing except to pick which key
    // to try, which is self-correcting (a tampered scope picks the wrong
    // key and the HMAC check rejects it).  Derived as owned values so the
    // blob borrow is released before `unmask` takes it mutably.
    let (key_type, kind, attrs, key_len, key_label) = {
        let meta = peek_metadata(body.masked_key)?;
        let meta_buf = pal.dma_alloc(io, meta.len())?;
        meta_buf.copy_from_slice(meta);
        let mut dec = MborDecoder::new(meta_buf);
        let metadata = DdiMaskedKeyMetadata::mbor_decode(&mut dec)
            .map_err(|_| HsmError::MaskedKeyDecodeFailed)?;

        // The partition unwrapping key is tagged `RsaUnwrap` and must
        // not be re-imported as a general key.
        if metadata.key_type == DdiKeyType::RsaUnwrap {
            return Err(HsmError::InvalidKeyType);
        }

        let kind = super::from_ddi::vault_kind_from_ddi(metadata.key_type)?;
        let attrs: HsmVaultKeyAttrs = metadata.key_attributes.into();

        // Copy the caller's key label out of the metadata scratch (the
        // scratch outlives this block but the borrow does not) so the
        // re-mask below can preserve it verbatim in the fresh envelope.
        let key_label = pal.dma_alloc(io, metadata.key_label.len())?;
        key_label.copy_from_slice(metadata.key_label);

        (
            metadata.key_type,
            kind,
            attrs,
            metadata.key_length as usize,
            key_label,
        )
    };

    // Authenticate-then-decrypt in place, copy out the primary key
    // material, and import it into the vault — all inside an allocation
    // scope so the (multi-KB for RSA) import scratch is freed before the
    // response frame is built.  Only the owned vault key id escapes; the
    // committed key is read back from vault storage below.  The masking key
    // is the per-session masking key for session-scoped keys, the partition
    // masking key (MK) otherwise; a wrong key (tampered scope) or tampered
    // blob fails the HMAC in `unmask` without leaking plaintext.
    let key_id = pal
        .alloc_scoped_async(io, async |_scope| -> HsmResult<HsmKeyId> {
            let layout = if attrs.session() {
                let session_mk = pal.session_masking_key(io, HsmSessId::from(sess_id))?;
                unmask(pal, io, session_mk, body.masked_key).await?
            } else {
                let mk_id = crate::part_state::part_mk_key_id(pal, io)?;
                let part_mk = pal.vault_key(io, mk_id)?;
                unmask(pal, io, part_mk, body.masked_key).await?
            };

            // Copy the primary key material (plaintext prefix) into a fresh
            // vault-import scratch buffer.  For ECC the trailing public
            // point is ignored here; the private scalar re-derives it.
            let key_buf = pal.dma_alloc(io, key_len)?;
            key_buf.copy_from_slice(
                &body.masked_key[layout.plaintext_offset..layout.plaintext_offset + key_len],
            );

            let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
            pal.vault_key_create(io, key_buf, kind, session_binding, attrs)
                .await
        })
        .await?;

    // The import scratch is freed.  Read the committed key back (from vault
    // storage, not the per-IO arena) to drive both the public-key
    // re-derivation and the fresh masked envelope.
    let priv_blob = pal.vault_key(io, key_id)?;

    // Asymmetric kinds return their public key, re-derived from the
    // committed private key so the host recovers the full keypair (this
    // also avoids trusting any untrusted trailing bytes in the blob).
    let pub_spec = match kind {
        HsmVaultKeyKind::Ecc256Private => Some((false, DdiKeyType::Ecc256Public)),
        HsmVaultKeyKind::Ecc384Private => Some((false, DdiKeyType::Ecc384Public)),
        HsmVaultKeyKind::Ecc521Private => Some((false, DdiKeyType::Ecc521Public)),
        HsmVaultKeyKind::Rsa2kPrivate | HsmVaultKeyKind::Rsa2kPrivateCrt => {
            Some((true, DdiKeyType::Rsa2kPublic))
        }
        HsmVaultKeyKind::Rsa3kPrivate | HsmVaultKeyKind::Rsa3kPrivateCrt => {
            Some((true, DdiKeyType::Rsa3kPublic))
        }
        HsmVaultKeyKind::Rsa4kPrivate | HsmVaultKeyKind::Rsa4kPrivateCrt => {
            Some((true, DdiKeyType::Rsa4kPublic))
        }
        _ => None,
    };
    let pub_key = if let Some((is_rsa, pub_kind)) = pub_spec {
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
    } else {
        None
    };

    // Re-mask the re-imported key under the *current* scope's masking key,
    // preserving the original key type, attributes, and label but recording
    // the current SVN via [`masked_metadata`](super::masking::masked_metadata).
    // The original blob is deliberately NOT echoed: the masking key / SVN may
    // have rolled since it was produced, so the host must persist this fresh
    // envelope to stay re-importable.  The envelope is written straight into
    // the reserved `masked_key` response region — no scratch buffer, no copy —
    // keeping the largest RSA-4096 keys within the per-IO DMA budget.
    let masking_key =
        super::masking::resolve_masking_key(pal, io, HsmSessId::from(sess_id), attrs.session())?;
    let metadata = super::masking::masked_metadata(
        pal,
        key_type,
        attrs,
        &key_label[..],
        priv_blob.len() as u16,
    )?;
    let masked_len = mask(pal, io, masking_key, priv_blob, &metadata, None).await?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr_sess(hdr, DdiOp::UnmaskKey, sess_id),
            buf,
        )?;
        let layout = DdiUnmaskKeyResp::reserve(
            &mut encoder,
            u16::from(key_id),
            pub_key,
            None,
            key_type,
            masked_len,
        )?;
        Ok((encoder.position(), layout))
    })?;

    // `mask` requires `out[..total_len]` zeroed on entry; the encoder does
    // not zero the reserved slot, so clear it before filling.
    let frame = DdiUnmaskKeyResp::from_layout(resp, &layout);
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
