// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-256-GCM `seal` / `open` implementation.
//!
//! Both operations are in-place on a single caller-owned
//! [`DmaBuf`](azihsm_fw_hsm_pal_traits::DmaBuf):
//!
//! * [`seal_gcm`] assembles `[HEADER | IV | AAD | DATA | TAG]` into
//!   the buffer (small memcpys for IV / AAD / plaintext, dictated
//!   by envelope assembly — the bulk GCM transform itself is in
//!   place) and asks the PAL to encrypt the `[AAD | DATA]` region
//!   with the tag written into the trailing slot.
//! * [`open_gcm`] re-parses the header, slices the regions, and
//!   asks the PAL to decrypt `[AAD | DATA]` in place with the tag
//!   read from the trailing slot. No copies, no moves, no scratch.
//!
//! Public dispatch lives in [`crate::ops`]; this module never sees
//! a non-`AES-256-GCM` `alg` value.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;

use crate::alg::AeadAlg;
use crate::envelope::region_offsets;
use crate::envelope::AeadEnvelope;
use crate::error::Error;
use crate::error::Result;
use crate::format::write_header;
use crate::format::Header;

/// AES-256-GCM seal. See [`crate::seal`] for the public entry
/// point that dispatches to this implementation.
///
/// Assumes `alg == AeadAlg::AesGcm256`; the dispatcher in
/// [`crate::ops`] is the only caller and guarantees this.
pub(crate) async fn seal_gcm(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    alg: AeadAlg,
    key: &DmaBuf,
    iv: &DmaBuf,
    aad: &DmaBuf,
    pt: &DmaBuf,
    buf: &mut DmaBuf,
) -> Result<usize> {
    // Length validation -------------------------------------------------
    if key.len() != alg.key_len() {
        return Err(Error::InvalidKeyLength);
    }
    if iv.len() != alg.iv_len() {
        return Err(Error::InvalidIvLength);
    }
    let aad_len = aad.len();
    let pt_len = pt.len();
    let envelope_len = alg.envelope_len(pt_len, aad_len);
    if buf.len() < envelope_len {
        return Err(Error::BufferTooSmall {
            needed: envelope_len,
        });
    }

    // Header (also validates aad_len against alg.aad_granularity()) ----
    write_header(buf, alg, aad_len)?;

    // Region offsets within `buf`. Computed without checked_add
    // because every term was already validated above (envelope_len
    // didn't saturate, so the partial sums fit too).
    let iv_off = crate::format::HEADER_LEN;
    let aad_off = iv_off + alg.iv_len();
    let data_off = aad_off + aad_len;
    let tag_off = data_off + pt_len;

    // Assemble [HEADER | IV | AAD | PT] into `buf` ---------------------
    // We use `get_mut` so a stray invariant violation surfaces as a
    // bounds error rather than a panic.
    let body = buf.get_mut(..envelope_len).ok_or(Error::BufferTooSmall {
        needed: envelope_len,
    })?;
    body.get_mut(iv_off..aad_off)
        .ok_or(Error::BufferTooSmall {
            needed: envelope_len,
        })?
        .copy_from_slice(iv);
    body.get_mut(aad_off..data_off)
        .ok_or(Error::BufferTooSmall {
            needed: envelope_len,
        })?
        .copy_from_slice(aad);
    body.get_mut(data_off..tag_off)
        .ok_or(Error::BufferTooSmall {
            needed: envelope_len,
        })?
        .copy_from_slice(pt);

    // Hand the `[AAD | DATA]` and `TAG` regions to the PAL. We split
    // `buf` so the borrow checker sees the two mutable regions as
    // disjoint sub-DmaBufs.
    let (_prefix, rest) = buf.split_at_mut(aad_off);
    // `rest` now starts at `aad_off`; lengths are relative to `rest`.
    let aad_dat_len = aad_len + pt_len;
    let (aad_dat, tag_region) = rest.split_at_mut(aad_dat_len);
    let (tag, _trailing) = tag_region.split_at_mut(alg.tag_len());

    crypto
        .gcm_encrypt_in_place(io, key, iv, aad_len, aad_dat, tag)
        .await
        .map_err(Error::Backend)?;

    Ok(envelope_len)
}

/// AES-256-GCM open. See [`crate::open`] for the public entry
/// point that dispatches to this implementation.
///
/// `header` has already been parsed and the alg has been verified
/// to be `AeadAlg::AesGcm256` by the dispatcher.
pub(crate) async fn open_gcm<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    buf: &'a mut DmaBuf,
    header: Header,
) -> Result<AeadEnvelope<'a>> {
    let total_len = buf.len();
    let (iv_off, aad_off, payload_off, tag_off) = region_offsets(header, total_len)?;

    if key.len() != header.alg.key_len() {
        return Err(Error::InvalidKeyLength);
    }

    // Split out [HEADER | IV | AAD+DATA | TAG] for the PAL call.
    let (prefix_with_iv, after_iv) = buf.split_at_mut(aad_off);
    let (_header_bytes, iv_region) = prefix_with_iv.split_at_mut(iv_off);

    // payload_off - aad_off == aad_len; tag_off - payload_off == data_len.
    let aad_data_len = tag_off - aad_off;
    let (aad_dat, tag_region) = after_iv.split_at_mut(aad_data_len);
    let (tag, _trailing) = tag_region.split_at_mut(header.alg.tag_len());

    // PAL decrypts in place; on tag mismatch the AAD+DATA region is
    // left in an unspecified state per the PAL contract.
    crypto
        .gcm_decrypt_in_place(io, key, iv_region, header.aad_len, tag, aad_dat)
        .await
        .map_err(|e| match e {
            HsmError::AesGcmDecryptTagDoesNotMatch => Error::AuthFailed,
            other => Error::Backend(other),
        })?;

    // Re-borrow `buf` immutably to construct the DmaBuf sub-views.
    // All ranges are validated by `region_offsets`; the indexed
    // accesses below cannot panic.
    let view = &*buf;
    Ok(AeadEnvelope {
        alg: header.alg,
        iv: &view[iv_off..aad_off],
        aad: &view[aad_off..payload_off],
        payload: &view[payload_off..tag_off],
        tag: &view[tag_off..total_len],
    })
}
