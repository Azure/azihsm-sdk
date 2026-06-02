// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetSessionEncryptionKey command handler.
//!
//! Returns the session-encryption public key, a nonce, and a signature
//! over the public key (signed with the partition identity key). This
//! is a NoSession command and is the bootstrap for [`DdiOp::OpenSession`]:
//! the host uses the returned public key + nonce to wrap the session
//! credential it then sends in [`DdiOp::OpenSession`].
//!
//! Uses the encode-frame-then-fill pattern: all variable fields are
//! filled directly into the encoder-reserved slots — zero intermediate
//! copies.

use azihsm_fw_ddi_mbor_types::get_session_encryption_key::DdiGetSessionEncryptionKeyReq;
use azihsm_fw_ddi_mbor_types::get_session_encryption_key::DdiGetSessionEncryptionKeyResp;
use azihsm_fw_ddi_mbor_types::DdiPublicKeyFrameParams;

use super::*;

/// Handle DdiGetSessionEncryptionKeyCmd.
///
/// Fails up-front with [`HsmError::CredentialsNotEstablished`] if the
/// partition does not yet have a user credential — the session
/// encryption key is meaningless before a credential is established
/// (the host would have nothing to wrap into the OpenSession request).
///
/// Unlike the `EstablishCred` encryption key, the session encryption
/// key is **persistent** across sessions — it is created at partition
/// enable and kept for the lifetime of the partition.  No clearing or
/// rotation is performed here.
pub(crate) async fn get_session_encryption_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetSessionEncryptionKeyReq = decoder.decode_data()?;

    if !pal.part_is_credential_set(io)? {
        return Err(HsmError::CredentialsNotEstablished);
    }

    // Query sizes, then encode header + frame with reserved slots.
    let pub_key_len = pal.part_session_enc_pub_key(io, None)?;
    let nonce_len = pal.part_nonce(io, None)?;

    let digest = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
    let id_priv_key = pal.vault_key(io, pal.part_id_key_id(io)?)?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr(hdr, DdiOp::GetSessionEncryptionKey),
            buf,
        )?;
        let layout = DdiGetSessionEncryptionKeyResp::reserve(
            &mut encoder,
            DdiPublicKeyFrameParams {
                raw_len: pub_key_len,
                key_kind: DdiKeyType::Ecc384Public,
            },
            nonce_len,
            HsmEccCurve::P384.sig_len(),
        )?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiGetSessionEncryptionKeyResp::from_layout(resp, &layout);

    // Fill public key and nonce in-place.
    pal.part_session_enc_pub_key(io, Some(frame.pub_key.raw))?;
    pal.part_nonce(io, Some(frame.nonce))?;

    // Hash pub key, then sign directly into the signature slot.
    pal.hash(io, HsmHashAlgo::Sha384, frame.pub_key.raw, digest, true)
        .await?;
    pal.ecc_sign(
        io,
        HsmEccCurve::P384,
        id_priv_key,
        digest,
        frame.pub_key_signature,
    )
    .await?;

    Ok(resp)
}
