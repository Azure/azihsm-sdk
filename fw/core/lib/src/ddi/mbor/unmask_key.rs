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
    let (key_type, kind, attrs, key_len) = {
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
        (metadata.key_type, kind, attrs, metadata.key_length as usize)
    };

    // Authenticate-then-decrypt in place under the scope's masking key: the
    // per-session masking key for session-scoped keys, the partition
    // masking key (MK) otherwise.  A wrong key (tampered scope) or a
    // tampered blob fails the HMAC here without leaking plaintext.
    let layout = if attrs.session() {
        let session_mk = pal.session_masking_key(io, HsmSessId::from(sess_id))?;
        unmask(pal, io, session_mk, body.masked_key).await?
    } else {
        let mk_id = crate::part_state::part_mk_key_id(pal, io)?;
        let part_mk = pal.vault_key(io, mk_id)?;
        unmask(pal, io, part_mk, body.masked_key).await?
    };

    // Copy the primary key material (plaintext prefix) into a fresh
    // vault-import scratch buffer.  For ECC the trailing public point is
    // ignored here; the private scalar alone re-derives it on import.
    let key_buf = pal.dma_alloc(io, key_len)?;
    key_buf.copy_from_slice(
        &body.masked_key[layout.plaintext_offset..layout.plaintext_offset + key_len],
    );

    let session_binding = attrs.session().then_some(HsmSessId::from(sess_id));
    let key_id: u16 = pal
        .vault_key_create(io, key_buf, kind, session_binding, attrs)
        .await?
        .into();

    // Asymmetric kinds return their public key, re-derived from the
    // imported private key so the host recovers the full keypair (this
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
    let pub_out = if let Some((is_rsa, pub_kind)) = pub_spec {
        let pub_len = if is_rsa {
            pal.rsa_priv_pub_key(io, key_buf, None)?
        } else {
            pal.ecc_priv_pub_key(io, key_buf, None).await?
        };
        let pub_buf = pal.dma_alloc(io, pub_len)?;
        if is_rsa {
            pal.rsa_priv_pub_key(io, key_buf, Some(pub_buf))?;
        } else {
            pal.ecc_priv_pub_key(io, key_buf, Some(pub_buf)).await?;
        }
        Some((pub_buf, pub_kind))
    } else {
        None
    };

    let resp = pal.dma_alloc_var(io, |buf| {
        super::encode_resp(
            &super::success_hdr_sess(hdr, DdiOp::UnmaskKey, sess_id),
            &DdiUnmaskKeyResp {
                key_id,
                pub_key: pub_out.map(|(raw, key_kind)| DdiPublicKey { raw, key_kind }),
                bulk_key_id: None,
                kind: key_type,
                masked_key: &[],
            },
            buf,
        )
    })?;
    Ok(resp)
}
