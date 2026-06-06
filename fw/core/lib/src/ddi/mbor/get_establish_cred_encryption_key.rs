// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI GetEstablishCredEncryptionKey command handler.
//!
//! Returns the establish-credential encryption public key, a nonce, and
//! a signature over the public key (signed with the partition identity
//! key). This is a NoSession command.
//!
//! Uses the encode-frame-then-fill pattern: all variable fields are
//! filled directly into the encoder-reserved slots — zero intermediate
//! copies.

use azihsm_fw_ddi_mbor_types::get_establish_cred_encryption_key::DdiGetEstablishCredEncryptionKeyReq;
use azihsm_fw_ddi_mbor_types::get_establish_cred_encryption_key::DdiGetEstablishCredEncryptionKeyResp;
use azihsm_fw_ddi_mbor_types::DdiPublicKeyFrameParams;

use super::*;

/// Handle DdiGetEstablishCredEncryptionKeyCmd.
pub(crate) async fn get_establish_cred_encryption_key<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let _body: DdiGetEstablishCredEncryptionKeyReq = decoder.decode_data()?;

    // Key must exist (not yet consumed by EstablishCredential).
    pal.part_establish_cred_key_id(io)?
        .ok_or(HsmError::KeyNotFound)?;

    // Query sizes, then encode header + frame with reserved slots.
    let pub_key_len = pal.part_establish_cred_pub_key(io, None)?;
    let nonce_len = pal.part_nonce(io, None)?;

    let digest = pal.dma_alloc(io, HsmHashAlgo::Sha384.digest_len())?;
    let id_priv_key = pal.vault_key(io, pal.part_id_key_id(io)?)?;

    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder = super::encode_resp_hdr(
            &super::success_hdr(hdr, DdiOp::GetEstablishCredEncryptionKey),
            buf,
        )?;
        let layout = DdiGetEstablishCredEncryptionKeyResp::reserve(
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
    let frame = DdiGetEstablishCredEncryptionKeyResp::from_layout(resp, &layout);

    // Fill public key and nonce in-place.
    pal.part_establish_cred_pub_key(io, Some(frame.pub_key.raw))?;
    pal.part_nonce(io, Some(frame.nonce))?;

    // Hash pub key directly in wire-LE (PAL's `ecc_sign` digest
    // contract), then sign into the signature slot.
    pal.hash(io, HsmHashAlgo::Sha384, frame.pub_key.raw, digest, false)
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
