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

    // Validate the digest_algo enum is supported and read the algo's native
    // digest size — the host's `digest_pre_encode` LE-reverses
    // `input_array.len()` bytes and zero-pads the rest to 68 wire bytes, so
    // the leading `real_digest_len` bytes are the actual digest in wire-LE
    // form and the remainder is zero. The slice handed to the PAL is widened
    // to the curve field width below (see `sign_len`); each PAL is
    // responsible for any endianness flip its underlying primitive requires
    // (e.g. std PAL reverses to BE for OpenSSL; real-HW PALs pass through to
    // the PKA engine).
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

    // The PKA engine DMA-reads a word-aligned, field-width operand for the
    // digest (e.g. 68 bytes for P-521), while the driver only validates
    // `hash.len() >= hash_size` (64 for P-521). The slice handed below is
    // widened to the field width but its backing must cover the full wire
    // coordinate width, or the engine would read past the request buffer into
    // adjacent memory. The host always zero-pads `digest` to this width; reject
    // anything shorter defensively so a malformed frame cannot trigger an
    // out-of-bounds operand read.
    if body.digest.len() < curve.wire_coord_len() {
        return Err(HsmError::InvalidArg);
    }

    // Widen the digest slice to at least the curve's ECDSA field width. The
    // leading `real_digest_len` bytes are the digest (wire-LE) and the padding
    // beyond is zero, so a short digest (e.g. a SHA-256 digest signed with a
    // P-384 key) is zero-extended up to the field width without any copy, and
    // the operand stays backed by the padded wire buffer. A digest longer than
    // the field is passed through so the std PAL's OpenSSL applies ECDSA
    // leftmost-bits truncation; the uno PKA consumes only its field-width
    // operand (full truncation for over-long digests is future FIPS ACVP work).
    let sign_len = real_digest_len.max(curve.ecdsa_digest_len());
    pal.ecc_sign(
        io,
        curve,
        priv_key,
        &body.digest[..sign_len],
        frame.signature,
    )
    .await?;

    Ok(resp)
}
