// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public surface: [`seal`], [`open`], [`inspect`], and the types
//! they hand to callers.
//!
//! This is the only module re-exported from the parent. All other
//! submodules are `pub(crate)` implementation detail.
//!
//! [`seal`] and [`open`] are thin dispatchers that validate
//! algorithm-agnostic invariants, then forward to the per-algorithm
//! implementation. Adding a new AEAD variant means:
//!
//! 1. Add a new [`AeadAlg`] discriminant (and the per-alg
//!    `key_len` / `iv_len` / `tag_len` / `aad_granularity` arms).
//! 2. Add `seal_xxx` / `open_xxx` in a sibling private module.
//! 3. Add one new arm in each `match` below. The public signatures
//!    never change.
//!
//! [`inspect`] is algorithm-agnostic — every supported algorithm
//! uses the same `[HEADER | IV | AAD | DATA | TAG]` wire layout —
//! so it lives here for surface symmetry rather than dispatching.

pub use super::alg::AeadAlg;
pub use super::envelope::AeadEnvelope;
use super::envelope::region_offsets;
pub use super::format::FORMAT_TAG;
pub use super::format::HEADER_LEN;
pub use super::format::MAX_AAD_LEN;
use super::format::is_valid_aad_len;
use super::format::read_header;
use super::gcm::open_gcm;
use super::gcm::seal_gcm;
use crate::AesKey;
use crate::CryptoError;

/// Seal `pt` and `aad` into `buf` as an AEAD envelope.
///
/// Follows the firmware **query-size-then-fill** convention: pass
/// `buf = None` to learn the required envelope length without
/// touching crypto, then call again with `Some(&mut buf)` sized at
/// least to that length to actually seal.
///
/// Dispatches on `alg`. In v1 the only accepted variant is
/// [`AeadAlg::AesGcm256`].
///
/// # Parameters
///
/// * `alg`  — selects the AEAD primitive.
/// * `key`  — AEAD key. Its size (`key.size()`) must equal
///   `alg.key_len()`; validated only when `buf` is `Some`.
/// * `iv`   — nonce (`alg.iv_len()` bytes; must be unique per
///   encryption with the same key; validated only when `buf` is
///   `Some`).
/// * `aad`  — additional authenticated data; length must be `0` or
///   a multiple of `alg.aad_granularity()`, and `<= MAX_AAD_LEN`.
///   Validated in both modes — an illegal AAD length is not a
///   valid query.
/// * `pt`   — plaintext to encrypt.
/// * `buf`  — `None` for a size query; `Some(out)` to seal, where
///   `out.len() >= alg.envelope_len(pt.len(), aad.len())`.
///
/// # Returns
///
/// * `Ok(n)`  — the envelope length in bytes. When `buf` is
///   `Some`, exactly `n` bytes have been written at `&out[..n]`.
/// * `Err(_)` — see [`CryptoError`].
pub fn seal(
    alg: AeadAlg,
    key: &AesKey,
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    buf: Option<&mut [u8]>,
) -> Result<usize, CryptoError> {
    if !is_valid_aad_len(aad.len(), alg.aad_granularity()) {
        return Err(CryptoError::AeadEnvelopeInvalidAadLength);
    }
    let total = alg.envelope_len(pt.len(), aad.len());
    let Some(buf) = buf else {
        return Ok(total);
    };
    let n = match alg {
        AeadAlg::AesGcm256 => seal_gcm(alg, key, iv, aad, pt, buf)?,
    };
    Ok(n)
}

/// In-place open. Parse the envelope in `buf`, verify the
/// authentication tag, decrypt the `DATA` region in place, and
/// return a borrowed [`AeadEnvelope`] view whose `payload` field
/// references the plaintext.
///
/// Dispatches on the `alg` byte read from the envelope header.
///
/// # Parameters
///
/// * `key` — AEAD key. Its size (`key.size()`) must match the
///   `alg.key_len()` for the algorithm encoded in the envelope
///   header.
/// * `buf` — the complete envelope. `buf.len()` is treated as the
///   exact envelope length.
///
/// # Returns
///
/// * `Ok(envelope)` — tag verified and `payload` decrypted in
///   place.
/// * `Err(_)` — see [`CryptoError`]. A tag mismatch surfaces as
///   [`CryptoError::GcmDecryptionFailed`].
pub fn open<'a>(key: &AesKey, buf: &'a mut [u8]) -> Result<AeadEnvelope<'a>, CryptoError> {
    let header = read_header(buf)?;
    let env = match header.alg {
        AeadAlg::AesGcm256 => open_gcm(key, buf, header)?,
    };
    Ok(env)
}

/// Parse an envelope header and return a borrowed [`AeadEnvelope`]
/// view without decrypting or authenticating.
///
/// `payload` references the ciphertext bytes in `buf`. The tag is
/// **not** verified; use [`open`] when authenticity matters.
///
/// Algorithm-agnostic: every supported algorithm shares the
/// `[HEADER | IV | AAD | DATA | TAG]` wire layout.
///
/// # Errors
/// * [`CryptoError::GcmBufferTooSmall`] — `buf.len()` is shorter
///   than the minimum envelope length implied by the parsed header.
/// * [`CryptoError::AeadEnvelopeInvalidFormat`] — bad magic byte.
/// * [`CryptoError::AeadEnvelopeUnsupportedAlg`] — `alg` byte not
///   supported in v1.
/// * [`CryptoError::AeadEnvelopeInvalidAadLength`] — encoded
///   `aad_len` violates the algorithm's AAD granularity.
pub fn inspect(buf: &[u8]) -> Result<AeadEnvelope<'_>, CryptoError> {
    let header = read_header(buf)?;
    let (iv_off, aad_off, payload_off, tag_off) = region_offsets(header, buf.len())?;
    let iv = buf
        .get(iv_off..aad_off)
        .ok_or(CryptoError::GcmBufferTooSmall)?;
    let aad = buf
        .get(aad_off..payload_off)
        .ok_or(CryptoError::GcmBufferTooSmall)?;
    let payload = buf
        .get(payload_off..tag_off)
        .ok_or(CryptoError::GcmBufferTooSmall)?;
    let tag = buf.get(tag_off..).ok_or(CryptoError::GcmBufferTooSmall)?;
    Ok(AeadEnvelope {
        alg: header.alg,
        iv,
        aad,
        payload,
        tag,
    })
}
