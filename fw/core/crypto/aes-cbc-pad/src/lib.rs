// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]

//! AES-CBC with PKCS#7 padding.
//!
//! This crate wraps the PAL's block-aligned [`HsmAes`] CBC API so
//! callers can encrypt arbitrary-length plaintext: [`aes_cbc_pkcs7_encrypt`]
//! adds PKCS#7 padding before encryption, and [`aes_cbc_pkcs7_decrypt`]
//! validates and removes it after decryption.
//!
//! ## PKCS#7 padding
//!
//! PKCS#7 always appends `pad_byte` value-`pad_byte` bytes where
//! `pad_byte = block_len - (pt.len() % block_len)`. When the
//! plaintext is already block-aligned the padding is a full extra
//! block of `0x10` bytes. The unpadder rejects any tail that does
//! not match this exact pattern with [`HsmError::AesDecryptFailed`].
//!
//! The crate is generic over the PAL — it only depends on the
//! [`HsmAes`] trait, not on any concrete PAL implementation.

use azihsm_fw_hsm_pal_traits::AesOp;
use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmAes;
use azihsm_fw_hsm_pal_traits::HsmAlloc;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

// =============================================================================
// Constants
// =============================================================================

/// AES block size in bytes.
const BLOCK: usize = 16;

// =============================================================================
// Helpers
// =============================================================================

/// Compute the PKCS#7-padded ciphertext length.
///
/// Always grows by 1..=BLOCK bytes (PKCS#7 never produces a
/// zero-byte pad — block-aligned inputs gain a full extra block).
///
/// # Parameters
/// * `pt_len` — plaintext length in bytes.
///
/// # Returns
/// * `pt_len + (BLOCK - pt_len % BLOCK)`.
pub const fn padded_len(pt_len: usize) -> usize {
    pt_len + BLOCK - (pt_len % BLOCK)
}

/// Apply PKCS#7 padding to the tail of a `padded_len(pt.len())` buffer.
///
/// Copies `pt` into `dst[..pt.len()]` and fills `dst[pt.len()..]`
/// with the pad-byte value.
fn apply_pkcs7_padding(dst: &mut [u8], pt: &[u8]) {
    let padded = dst.len();
    dst[..pt.len()].copy_from_slice(pt);
    let pad_byte = (padded - pt.len()) as u8;
    dst[pt.len()..padded].fill(pad_byte);
}

/// Validate PKCS#7 padding on the tail of a freshly-decrypted buffer
/// and return the unpadded length.
///
/// # Parameters
/// * `decrypted` — plaintext + padding (length is a multiple of
///   [`BLOCK`]).
///
/// # Returns
/// * `Ok(unpadded_len)` if the padding is well-formed.
///
/// # Errors
/// * [`HsmError::AesDecryptFailed`] if the trailing padding bytes do
///   not match the PKCS#7 pattern.
fn strip_pkcs7_padding(decrypted: &[u8]) -> HsmResult<usize> {
    let len = decrypted.len();
    let pad_byte = decrypted[len - 1];
    if pad_byte == 0 || pad_byte as usize > BLOCK {
        return Err(HsmError::AesDecryptFailed);
    }
    let pad_start = len - pad_byte as usize;
    if !decrypted[pad_start..len].iter().all(|&b| b == pad_byte) {
        return Err(HsmError::AesDecryptFailed);
    }
    Ok(pad_start)
}

// =============================================================================
// Public API
// =============================================================================

/// AES-CBC encrypt with PKCS#7 padding.
///
/// Pads `pt` to the next 16-byte boundary (always adds at least 1
/// byte of padding) and encrypts the padded buffer with AES-CBC.
///
/// # Type parameters
/// * `P` — any [`HsmAes`] PAL implementation.
///
/// # Parameters
/// * `pal` — PAL providing AES-CBC.
/// * `io` — I/O context forwarded to the PAL AES methods.
/// * `key` — AES key (16, 24, or 32 bytes).
/// * `iv` — 16-byte initialisation vector. Updated in place to the
///   last ciphertext block so the caller can chain CBC sessions.
/// * `pt` — plaintext of any length (including zero — the result is
///   then a single full block of pad bytes).
/// * `ct` — destination buffer; must be at least
///   [`padded_len(pt.len())`](padded_len) bytes long.
///
/// # Returns
/// * `Ok(padded_len)` — number of ciphertext bytes written to `ct`.
///
/// # Errors
/// * [`HsmError::InvalidArg`] if `ct` is shorter than the padded
///   length.
/// * Any [`HsmError`] surfaced by the PAL's CBC engine.
pub async fn aes_cbc_pkcs7_encrypt<P: HsmAes + HsmAlloc>(
    pal: &P,
    io: &impl HsmIo,
    key: &DmaBuf,
    iv: &mut [u8],
    pt: &[u8],
    ct: &mut DmaBuf,
) -> HsmResult<usize> {
    let padded = padded_len(pt.len());
    if ct.len() < padded {
        return Err(HsmError::InvalidArg);
    }

    if iv.len() != BLOCK {
        return Err(HsmError::InvalidArg);
    }

    let work = pal.dma_alloc(io, padded)?;
    apply_pkcs7_padding(work, pt);

    let iv_in = pal.dma_alloc(io, BLOCK)?;
    iv_in.copy_from_slice(iv);
    let iv_out = pal.dma_alloc(io, BLOCK)?;
    pal.aes_cbc_enc_dec_in_place(io, AesOp::Encrypt, key, work, iv_in, Some(iv_out))
        .await?;
    ct[..padded].copy_from_slice(work);
    iv.copy_from_slice(iv_out);
    Ok(padded)
}

/// AES-CBC decrypt with PKCS#7 unpadding.
///
/// Decrypts `ct` with AES-CBC, validates the PKCS#7 padding, and
/// returns the unpadded plaintext length.
///
/// # Type parameters
/// * `P` — any [`HsmAes`] PAL implementation.
///
/// # Parameters
/// * `pal` — PAL providing AES-CBC.
/// * `io` — I/O context forwarded to the PAL AES methods.
/// * `key` — AES key (16, 24, or 32 bytes).
/// * `iv` — 16-byte IV. Updated in place after decryption.
/// * `ct` — ciphertext; must be a non-empty whole number of 16-byte
///   blocks.
/// * `pt` — destination buffer; must be at least `ct.len()` bytes
///   long.
///
/// # Returns
/// * `Ok(pt_len)` — number of plaintext bytes (i.e. `ct.len()` minus
///   the validated PKCS#7 pad).
///
/// # Errors
/// * [`HsmError::InvalidArg`] if `ct` is empty, not a multiple of 16
///   bytes, or `pt` is shorter than `ct`.
/// * [`HsmError::AesDecryptFailed`] if the recovered padding is
///   invalid.
/// * Any [`HsmError`] surfaced by the PAL's CBC engine.
pub async fn aes_cbc_pkcs7_decrypt<P: HsmAes + HsmAlloc>(
    pal: &P,
    io: &impl HsmIo,
    key: &DmaBuf,
    iv: &mut [u8],
    ct: &DmaBuf,
    pt: &mut DmaBuf,
) -> HsmResult<usize> {
    let len = ct.len();
    if len == 0 || !len.is_multiple_of(BLOCK) || pt.len() < len {
        return Err(HsmError::InvalidArg);
    }

    if iv.len() != BLOCK {
        return Err(HsmError::InvalidArg);
    }

    let iv_in = pal.dma_alloc(io, BLOCK)?;
    iv_in.copy_from_slice(iv);
    let iv_out = pal.dma_alloc(io, BLOCK)?;
    pal.aes_cbc_enc_dec(io, AesOp::Decrypt, key, ct, iv_in, pt, Some(iv_out))
        .await?;
    iv.copy_from_slice(iv_out);
    strip_pkcs7_padding(&pt[..len])
}
