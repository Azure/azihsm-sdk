// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES-CBC-256 + HMAC-SHA-384 masking pipeline.
//!
//! Implements [`mask`]: a single async function that follows the
//! firmware `out: Option<&mut DmaBuf>` query-size-then-fill convention.
//! Metadata is supplied as a typed [`DdiMaskedKeyMetadata`] struct and
//! MBOR-encoded **directly** into the metadata slot of the output
//! buffer — no scratch buffer, no intermediate copy.
//!
//! ## No internal DMA allocations
//!
//! The function never calls `dma_alloc`.  All scratch space comes from
//! sub-slices of the caller's output buffer; the masking key is
//! consumed in place as two sub-views (low 32 B = AES key, high 48 B =
//! HMAC key) of the caller's [`DmaBuf`].
//!
//! ## In-place AES
//!
//! Because the plaintext length is always ≤ ciphertext length (custom
//! zero-pad-to-block scheme — no extra block when already aligned),
//! plaintext is copied into the ciphertext slot of the output buffer
//! and AES-CBC-encrypted in-place.
//!
//! ## Padding scheme
//!
//! Unlike PKCS#7, this implementation uses **minimal zero-padding**:
//! plaintext is zero-extended to the next multiple of the AES block
//! size, with **no padding at all when the plaintext is already
//! block-aligned**.  The decoder recovers the original plaintext
//! length from the metadata's `key_length` field.

use azihsm_fw_ddi_mbor::MborEncode;
use azihsm_fw_ddi_mbor::MborEncoder;
use azihsm_fw_ddi_mbor::MborLen;
use azihsm_fw_ddi_mbor::MborLenAccumulator;
use azihsm_fw_ddi_mbor_types::masked_key::DdiMaskedKeyMetadata;
use azihsm_fw_hsm_pal_traits::AesOp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;
use azihsm_fw_hsm_pal_traits::HsmHmac;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmRng;

use crate::cbc::format::MaskedKeyAesHeader;
use crate::cbc::format::MaskedKeyHeader;
use crate::cbc::format::AES_CBC_256_KEY_SIZE;
use crate::cbc::format::AES_CBC_IV_SIZE;
use crate::cbc::format::MASKING_KEY_AES_CBC_256_HMAC_384_LEN;

/// Build an authenticated-encryption "masked key" blob using
/// AES-CBC-256 + HMAC-SHA-384 (encrypt-then-MAC).
///
/// MBOR-encodes `metadata` directly into the metadata slot of `out` —
/// no scratch buffer, no intermediate copy.
///
/// Follows the firmware query-size-then-fill convention:
///
/// * `out == None` — returns the total blob length the caller must
///   allocate, **without** performing any crypto work or reading
///   `masking_key`.  Per-component length inputs are validated for
///   `u16` overflow.  Note that constraints enforced only by
///   `MborEncode` (for example `#[ddi(max_len = ...)]` on byte-slice
///   fields) are not re-validated in this path; an oversized
///   `metadata` will be rejected on a subsequent fill call.
/// * `out == Some(buf)` — `buf.len()` must be **at least** the
///   length returned by a prior size-only call with the same inputs;
///   extra trailing bytes are left untouched.  Fills `buf[..total_len]`
///   with a complete, HMAC-authenticated masked-key blob.
///
/// On any failure after `buf` has been mutated, the entire `buf` is
/// zeroed before returning the error so the caller's response staging
/// area never retains plaintext or an unauthenticated partial blob.
///
/// # Type parameters
///
/// * `P` — any PAL providing AES, HMAC, and RNG.
///
/// # Parameters
///
/// * `pal` — PAL providing AES, HMAC, and RNG.
/// * `io` — caller's I/O context (per-IO scope).
/// * `masking_key` — 80-byte DMA buffer: 32-byte AES-256 key (low
///   half) followed by 48-byte HMAC-SHA-384 key (high half).  Used
///   as sub-views; never copied.  Ignored when `out == None`.
/// * `plaintext` — raw bytes to mask.  Copied into the ciphertext
///   slot of `out` and encrypted in-place; the caller does **not**
///   need to pre-pad.  Trailing bytes inside the ciphertext slot
///   beyond `plaintext.len()` are zero-filled before encryption.
/// * `metadata` — masked-key metadata struct.  MBOR-encoded into the
///   metadata slot of `out` and bound by the trailing HMAC tag.
/// * `out` — DMA buffer of at least the encoded blob length, or
///   `None` to query the required length.  **Precondition:** when
///   `Some`, `out[..total_len]` must be zero on entry — the encoder
///   relies on this for `post_metadata_pad` bytes (visible on the
///   wire) and for the plaintext-staging tail inside the ciphertext
///   slot (input to AES).  Checked via `debug_assert!`.
///
/// # Returns
///
/// * `Ok(total_len)` — required (or written) blob length in bytes.
/// * `Err(HsmError::InvalidArg)` — malformed `masking_key` length,
///   output buffer size mismatch, or any per-field length
///   overflowing the wire-level `u16` width.
/// * `Err(HsmError::MetadataEncodeFailed)` — `metadata` could not be
///   MBOR-encoded (for example, a byte-slice field exceeds its
///   `#[ddi(max_len)]` cap).
/// * Any [`HsmError`] surfaced by the PAL RNG, AES, or HMAC drivers.
pub async fn mask<P>(
    pal: &P,
    io: &impl HsmIo,
    masking_key: &DmaBuf,
    plaintext: &[u8],
    metadata: &DdiMaskedKeyMetadata<'_>,
    out: Option<&mut DmaBuf>,
) -> HsmResult<usize>
where
    P: HsmAes + HsmHmac + HsmRng,
{
    // MBOR-encoded metadata length (no writes).
    let metadata_len = {
        let mut acc = MborLenAccumulator::default();
        metadata.mbor_len(&mut acc);
        acc.len()
    };

    let hdr = MaskedKeyAesHeader::new_cbc(metadata_len, plaintext.len())?;
    let total_len = hdr.total_len();

    // Size-query short-circuit.
    let Some(out) = out else {
        return Ok(total_len);
    };

    if masking_key.len() != MASKING_KEY_AES_CBC_256_HMAC_384_LEN || out.len() < total_len {
        return Err(HsmError::InvalidArg);
    }
    debug_assert!(
        out[..total_len].iter().all(|&b| b == 0),
        "mask: `out[..total_len]` must be zero on entry",
    );

    MaskedKeyHeader::new_cbc().write_into(out);
    hdr.write_into(&mut out[MaskedKeyHeader::SIZE..]);

    // MBOR-encode `metadata` directly into its slot inside `out`.
    let meta_off = hdr.metadata_offset();
    let encode_result = {
        let mut enc = MborEncoder::new(&mut out[meta_off..meta_off + metadata_len]);
        metadata
            .mbor_encode(&mut enc)
            .map_err(|_| HsmError::MetadataEncodeFailed)
            .and_then(|()| {
                // Defensive: `MborLen` and `MborEncode` must agree
                // exactly; mismatch implies a derive/codec bug.
                if enc.position() == metadata_len {
                    Ok(())
                } else {
                    Err(HsmError::MetadataEncodeFailed)
                }
            })
    };
    if let Err(e) = encode_result {
        out.fill(0);
        return Err(e);
    }

    let iv_off = hdr.iv_offset();
    let iv_len = AES_CBC_IV_SIZE;
    let ct_off = hdr.ciphertext_offset();
    let tag_off = hdr.tag_offset();

    if let Err(e) = pal.rng_fill_bytes(io, &mut out[iv_off..iv_off + iv_len]) {
        out.fill(0);
        return Err(e);
    }

    // Stage plaintext into the ciphertext slot for in-place encryption;
    // every error path from here must wipe `out` to avoid leaking
    // plaintext.
    out[ct_off..ct_off + plaintext.len()].copy_from_slice(plaintext);

    // AES-CBC-256 encrypt in-place; split at `ct_off` to disjoin the IV
    // (immutable) and ciphertext (mutable) sub-views.  AES key = low
    // 32 B of `masking_key`.
    let aes_result = {
        let (front, back) = out.split_at_mut(ct_off);
        let iv = &front[iv_off..iv_off + iv_len];
        let ct = &mut back[..hdr.ciphertext_len()];
        let aes_key = &masking_key[..AES_CBC_256_KEY_SIZE];
        pal.aes_cbc_enc_dec_in_place(io, AesOp::Encrypt, aes_key, ct, iv, None)
            .await
    };
    if let Err(e) = aes_result {
        out.fill(0);
        return Err(e);
    }

    // HMAC-SHA-384 over everything before the tag slot; HMAC key = high
    // 48 B of `masking_key`.
    let hmac_result = {
        let (tagged, tag_slot) = out.split_at_mut(tag_off);
        let hmac_key = &masking_key[AES_CBC_256_KEY_SIZE..];
        pal.hmac_sign(io, HsmHashAlgo::Sha384, hmac_key, tagged, tag_slot)
            .await
    };
    if let Err(e) = hmac_result {
        out.fill(0);
        return Err(e);
    }

    Ok(total_len)
}
