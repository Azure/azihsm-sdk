// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DDI EccSign command handler.
//!
//! Within an open session, look up an ECC private key by id and
//! produce a raw `r || s` signature over the host-supplied digest.
//! The digest must already be hashed by the host — firmware does no
//! hashing here.

use azihsm_fw_ddi_mbor_types::ecc_sign::DdiEccSignReq;
use azihsm_fw_ddi_mbor_types::ecc_sign::DdiEccSignResp;

use super::*;

/// Handle `DdiEccSignCmd`.
pub(crate) async fn ecc_sign<'p, P: HsmPal>(
    pal: &'p P,
    io: &impl HsmIo,
    decoder: &mut DdiDecoder<'_>,
    hdr: &DdiReqHdr,
) -> HsmResult<&'p DmaBuf> {
    let body: DdiEccSignReq = decoder.decode_data()?;

    let sess_id = hdr.sess_id.ok_or(HsmError::SessionExpected)?;

    // Validate the digest_algo enum is supported and pin the slice
    // length to the algo's native digest size — the host's
    // `digest_pre_encode` LE-reverses `input_array.len()` bytes and
    // zero-pads the rest to 68 wire bytes, so the leading
    // `real_digest_len` bytes are the actual digest in wire-LE form.
    // We hand that sub-slice straight to the PAL, which is
    // responsible for any endianness flip its underlying primitive
    // requires (e.g. std PAL reverses to BE for OpenSSL; real-HW
    // PALs pass through to the PKA engine).
    let pal_algo = super::from_ddi::hash(body.digest_algo)?;
    let real_digest_len = pal_algo.digest_len();
    if body.digest.len() < real_digest_len {
        return Err(HsmError::InvalidArg);
    }

    let key_id = HsmKeyId::from(body.key_id);
    let vault_kind = pal.vault_key_kind(io, key_id)?;
    let curve = super::from_pal::ecc_curve(vault_kind)?;
    let vault_attrs = pal.vault_key_attrs(io, key_id)?;
    if !vault_attrs.sign() {
        return Err(HsmError::InvalidPermissions);
    }
    let priv_key = pal.vault_key(io, key_id)?;

    // Sign directly into the wire-format signature slot.  The PAL
    // emits `r || s` in LE with P-521 trailing pad bytes, so we just
    // reserve `curve.wire_sig_len()` bytes and hand the slot through.
    let wire_len = curve.wire_sig_len();
    let (resp, layout) = pal.dma_alloc_var_with(io, |buf| {
        let mut encoder =
            super::encode_resp_hdr(&super::success_hdr_sess(hdr, DdiOp::EccSign, sess_id), buf)?;
        let layout = DdiEccSignResp::reserve(&mut encoder, wire_len)?;
        Ok((encoder.position(), layout))
    })?;
    let frame = DdiEccSignResp::from_layout(resp, &layout);
    pal.ecc_sign(
        io,
        curve,
        priv_key,
        &body.digest[..real_digest_len],
        frame.signature,
    )
    .await?;

    Ok(resp)
}
