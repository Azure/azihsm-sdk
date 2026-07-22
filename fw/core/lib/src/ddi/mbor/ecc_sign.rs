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

    // Two curve-specific widths matter here, each with a single source of truth:
    //   * the digest VALUE width, `curve.ecdsa_digest_len()` (32 / 48 / 64) —
    //     the meaningful digest bytes that are signed (also what the std PAL's
    //     OpenSSL and the UPKA driver's `hash.len() >= hash_size` check bound);
    //     and
    //   * the PKA DMA OPERAND width, `curve.wire_coord_len()` (32 / 48 / 68) —
    //     the word-aligned field the engine actually DMA-reads for the digest.
    // They coincide for P-256/P-384 but differ for P-521 (64 vs 68): the 66-byte
    // P-521 field is zero-padded to a 32-bit word boundary. The engine reads the
    // full operand width regardless of the slice length handed to the driver, so
    // the driver's `hash_size` check alone is NOT sufficient to keep the read in
    // bounds (verified on HW: a 64-byte-backed P-521 digest over-reads and
    // yields a wrong signature). Enforce the operand-width invariants here, where
    // the whole `digest` buffer is visible, rather than at the driver, which only
    // sees the sliced view's length.
    //
    // The host zero-pads `digest` to the operand width (`digest_pre_encode`
    // always emits 68 wire bytes, so a conforming frame never trips these). We
    // require that (1) the buffer covers the operand width, so the DMA read stays
    // in bounds, and (2) every byte between the declared digest and the operand
    // width is zero, since the read folds them into the signed value — so the
    // signature is well-defined over exactly the declared digest even for a
    // malformed frame.
    //
    // Cost: the scan below touches only the padding region
    // (`operand_len - real_digest_len`), once per sign — not the whole buffer.
    // For a digest matched to its curve (P-256+SHA-256, P-384+SHA-384,
    // P-521+SHA-512) that region is 0-4 bytes (only the P-521 `[64..68]` wire
    // pad), so the common path is effectively free; the worst case is a short
    // digest on P-521 (~36 bytes), trivial next to the PKA sign.
    let operand_len = curve.wire_coord_len();
    if body.digest.len() < operand_len {
        return Err(HsmError::InvalidArg);
    }
    if body.digest[real_digest_len.min(operand_len)..operand_len]
        .iter()
        .any(|&b| b != 0)
    {
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
