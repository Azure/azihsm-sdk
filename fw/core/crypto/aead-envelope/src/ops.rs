// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public surface: [`seal`], [`open`], and the types they hand to
//! callers.
//!
//! This is the only module re-exported from the crate root. All
//! other modules are `pub(crate)` implementation detail.
//!
//! [`seal`] and [`open`] are thin dispatchers: they validate
//! algorithm-agnostic invariants, then forward to the per-algorithm
//! implementation in a sibling module. Adding a new AEAD variant
//! means adding a new [`AeadAlg`] discriminant, a new `seal_xxx` /
//! `open_xxx` private impl, and one new arm in each `match` below.
//! The public signatures never change.
//!
//! ```text
//! seal(alg, ...) ──► match alg {
//!                       AesGcm256 => seal_gcm(...),
//!                       // future: Aes128Gcm     => seal_gcm(...),
//!                       // future: AesCbcHmac256 => seal_cbc_hmac(...),
//!                       // future: ChaChaPoly    => seal_chachapoly(...),
//!                   }
//!
//! open(...) ──► read_header(buf)
//!             ──► match header.alg {
//!                     AesGcm256 => open_gcm(...),
//!                     // future arms ...
//!                 }
//! ```

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmCrypto;
use azihsm_fw_hsm_pal_traits::HsmIo;
use azihsm_fw_hsm_pal_traits::HsmResult;

pub use crate::alg::AeadAlg;
pub use crate::envelope::AeadEnvelope;
use crate::error::Error;
pub use crate::error::Error as AeadError;
use crate::format::is_valid_aad_len;
use crate::format::read_header;
pub use crate::format::FORMAT_TAG;
pub use crate::format::HEADER_LEN;
pub use crate::format::MAX_AAD_LEN;
use crate::gcm::open_gcm;
use crate::gcm::seal_gcm;

/// Seal `pt` and `aad` into `buf` as an AEAD envelope.
///
/// Follows the firmware **query-size-then-fill** convention: pass
/// `buf = None` to learn the required envelope length without
/// touching crypto/I/O, then call again with `Some(&mut buf)` sized
/// at least to that length to actually seal.
///
/// Dispatches on `alg`. In v1 the only accepted variant is
/// [`AeadAlg::AesGcm256`].
///
/// # Parameters
///
/// * `crypto` — any PAL implementing [`HsmCrypto`].
/// * `io`     — caller's I/O context (per-IO scope).
/// * `alg`    — selects the AEAD primitive; must satisfy the
///   per-algorithm constraints on `key`/`iv`/`aad` lengths (see
///   [`AeadAlg::key_len`], [`AeadAlg::iv_len`],
///   [`AeadAlg::aad_granularity`]).
/// * `key`    — AEAD key (`alg.key_len()` bytes). Validated only
///   when `buf` is `Some`.
/// * `iv`     — nonce (`alg.iv_len()` bytes). Must be unique per
///   encryption with the same key. Validated only when `buf` is
///   `Some`.
/// * `aad`    — additional authenticated data; length must be `0`
///   or a multiple of `alg.aad_granularity()`, and `<=
///   MAX_AAD_LEN`. Validated in both modes — an illegal AAD
///   length is not a valid query.
/// * `pt`     — plaintext to encrypt.
/// * `buf`    — `None` for a size query; `Some(out)` to seal, where
///   `out.len() >= alg.envelope_len(pt.len(), aad.len())`.
///
/// # Returns
///
/// * `Ok(n)`  — the envelope length in bytes. When `buf` is
///   `Some`, exactly `n` bytes have been written at `&out[..n]`.
/// * `Err(_)` — see [`AeadError`] for the precise failure modes;
///   mapped to [`HsmError`](azihsm_fw_hsm_pal_traits::HsmError) via
///   [`From`].
pub async fn seal(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    alg: AeadAlg,
    key: &DmaBuf,
    iv: &DmaBuf,
    aad: &DmaBuf,
    pt: &DmaBuf,
    buf: Option<&mut DmaBuf>,
) -> HsmResult<usize> {
    // Validate AAD length against the alg's granularity (and the
    // wire-format `u16` cap) up-front so a `None` size query still
    // surfaces an illegal AAD length rather than silently returning
    // a size that could never be filled.
    if !is_valid_aad_len(aad.len(), alg.aad_granularity()) {
        return Err(Error::InvalidAadLength.into());
    }
    let total = alg.envelope_len(pt.len(), aad.len());

    // Size-query short-circuit.
    let Some(buf) = buf else {
        return Ok(total);
    };

    let n = match alg {
        AeadAlg::AesGcm256 => seal_gcm(crypto, io, alg, key, iv, aad, pt, buf).await?,
    };
    Ok(n)
}

/// In-place open. Parse the envelope in `buf`, verify the
/// authentication tag, decrypt the `DATA` region in place, and
/// return a borrowed [`AeadEnvelope`] view whose `payload` field
/// references the plaintext.
///
/// Dispatches on the `alg` byte read from the envelope header. In
/// v1 the only accepted variant is [`AeadAlg::AesGcm256`].
///
/// # Parameters
///
/// * `crypto` — any PAL implementing [`HsmCrypto`].
/// * `io`     — caller's I/O context (per-IO scope).
/// * `key`    — AEAD key. The required length is determined by the
///   `alg` byte parsed from the header.
/// * `buf`    — the complete envelope. `buf.len()` is treated as
///   the exact envelope length.
///
/// # Returns
///
/// * `Ok(envelope)` — tag verified and `payload` decrypted in
///   place.
/// * `Err(_)` — see [`AeadError`]. A tag mismatch surfaces as
///   [`AeadError::AuthFailed`] mapped to
///   [`HsmError::AesGcmDecryptTagDoesNotMatch`](azihsm_fw_hsm_pal_traits::HsmError::AesGcmDecryptTagDoesNotMatch).
pub async fn open<'a>(
    crypto: &impl HsmCrypto,
    io: &impl HsmIo,
    key: &DmaBuf,
    buf: &'a mut DmaBuf,
) -> HsmResult<AeadEnvelope<'a>> {
    let header = read_header(buf)?;
    let env = match header.alg {
        AeadAlg::AesGcm256 => open_gcm(crypto, io, key, buf, header).await?,
    };
    Ok(env)
}
