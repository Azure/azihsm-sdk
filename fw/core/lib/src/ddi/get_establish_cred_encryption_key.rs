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
pub(crate) async fn get_establish_cred_encryption_key<'a, P: HsmPal>(
    hdr: &DdiReqHdr,
    decoder: &mut DdiDecoder<'_>,
    part_id: HsmPartId,
    pal: &P,
    fmem: &mut [u8],
    smem: &'a mut [u8],
) -> HsmResult<&'a [u8]> {
    let _body: DdiGetEstablishCredEncryptionKeyReq = decoder.decode_data()?;

    // Key must exist (not yet consumed by EstablishCredential).
    pal.part_establish_cred_key_id(part_id)?
        .ok_or(HsmError::KeyNotFound)?;

    // Query sizes, then encode header + frame with reserved slots.
    let pub_key_len = pal.part_establish_cred_pub_key(part_id, None)?;
    let nonce_len = pal.part_nonce(part_id, None)?;

    let mut encoder = ddi::encode_resp_hdr(
        &ddi::success_hdr(hdr, DdiOp::GetEstablishCredEncryptionKey),
        smem,
    )?;
    let frame = DdiGetEstablishCredEncryptionKeyResp::frame(
        &mut encoder,
        DdiPublicKeyFrameParams {
            raw_len: pub_key_len,
            key_kind: DdiKeyType::Ecc384Public,
        },
        nonce_len,
        HsmEccCurve::P384.sig_len(),
    )?;
    let total = encoder.position();

    // Fill public key and nonce in-place.
    pal.part_establish_cred_pub_key(part_id, Some(frame.pub_key.raw))?;
    pal.part_nonce(part_id, Some(frame.nonce))?;

    // Hash pub key, then sign directly into the signature slot.
    // Digest goes in fmem to keep the async future small.
    let id_priv_key = pal.vault_key(part_id, pal.part_id_key_id(part_id)?)?;

    let digest = &mut fmem[..HsmHashAlgo::Sha384.digest_len()];
    pal.hash(HsmHashAlgo::Sha384, frame.pub_key.raw, digest)
        .await?;
    pal.ecc_sign(
        HsmEccCurve::P384,
        id_priv_key,
        digest,
        frame.pub_key_signature,
    )
    .await?;

    Ok(&smem[..total])
}
