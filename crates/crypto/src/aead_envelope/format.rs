// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format constants and header read/write helpers.
//!
//! ```text
//!   off    0     1     2     3     4     5         6     7     8
//!         ┌─────┬─────┬─────┬─────┬─────┬─────────┬─────────────┐
//!         │ 'A' │ 'E' │ 'A' │ 'D' │ alg │ rsv (0) │ aad_len_be  │
//!         └─────┴─────┴─────┴─────┴─────┴─────────┴─────────────┘
//!         └───────── magic ───────┘
//! ```

use super::alg::AeadAlg;
use crate::CryptoError;

/// 4-byte ASCII magic at offset 0 of every envelope: `b"AEAD"`.
pub const FORMAT_TAG: [u8; 4] = *b"AEAD";

/// Fixed header length in bytes (`magic | alg | rsv | aad_len_be`).
pub const HEADER_LEN: usize = 8;

/// Maximum AAD length representable in the 2-byte `aad_len` field.
pub const MAX_AAD_LEN: usize = u16::MAX as usize;

/// Returns `true` iff `n` is a legal `aad_len` value for an
/// algorithm with the given AAD granularity:
///
/// * `n <= MAX_AAD_LEN` (fits in the wire `aad_len_be` field), and
/// * `n == 0` or `n % granularity == 0`.
pub(crate) const fn is_valid_aad_len(n: usize, granularity: usize) -> bool {
    n <= MAX_AAD_LEN && n.is_multiple_of(granularity)
}

/// Parsed envelope header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Header {
    pub alg: AeadAlg,
    pub aad_len: usize,
}

/// Parse the 8-byte envelope header at the start of `buf`.
///
/// The `aad_len` field is validated against the AAD granularity of
/// the parsed algorithm (see [`AeadAlg::aad_granularity`]). The
/// reserved byte at offset 5 is validated to be `0`.
///
/// # Errors
/// * [`CryptoError::GcmBufferTooSmall`] — `buf.len() < HEADER_LEN`.
/// * [`CryptoError::AeadEnvelopeInvalidFormat`] — magic bytes do
///   not match [`FORMAT_TAG`] or the reserved byte is non-zero.
/// * [`CryptoError::AeadEnvelopeUnsupportedAlg`] — `alg` byte not
///   supported in v1.
/// * [`CryptoError::AeadEnvelopeInvalidAadLength`] — `aad_len_be`
///   violates the alg's granularity.
pub(crate) fn read_header(buf: &[u8]) -> Result<Header, CryptoError> {
    let head = buf
        .get(..HEADER_LEN)
        .ok_or(CryptoError::GcmBufferTooSmall)?;
    if head[..4] != FORMAT_TAG {
        return Err(CryptoError::AeadEnvelopeInvalidFormat);
    }
    let alg = AeadAlg::from_u8(head[4])?;
    if head[5] != 0 {
        return Err(CryptoError::AeadEnvelopeInvalidFormat);
    }
    let aad_len = u16::from_be_bytes([head[6], head[7]]) as usize;
    if !is_valid_aad_len(aad_len, alg.aad_granularity()) {
        return Err(CryptoError::AeadEnvelopeInvalidAadLength);
    }
    Ok(Header { alg, aad_len })
}

/// Write the 8-byte envelope header at the start of `buf`. The
/// reserved byte at offset 5 is always written as `0`.
///
/// `aad_len` is validated against `alg.aad_granularity()` before
/// any bytes are written.
///
/// # Errors
/// * [`CryptoError::AeadEnvelopeInvalidAadLength`] — `aad_len`
///   violates the alg's granularity.
/// * [`CryptoError::GcmBufferTooSmall`] — `buf.len() < HEADER_LEN`.
pub(crate) fn write_header(
    buf: &mut [u8],
    alg: AeadAlg,
    aad_len: usize,
) -> Result<(), CryptoError> {
    if !is_valid_aad_len(aad_len, alg.aad_granularity()) {
        return Err(CryptoError::AeadEnvelopeInvalidAadLength);
    }
    let head = buf
        .get_mut(..HEADER_LEN)
        .ok_or(CryptoError::GcmBufferTooSmall)?;
    let aad_be = (aad_len as u16).to_be_bytes();
    head[..4].copy_from_slice(&FORMAT_TAG);
    head[4] = alg.as_u8();
    head[5] = 0;
    head[6] = aad_be[0];
    head[7] = aad_be[1];
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn valid_aad_len_accepts_zero_and_multiples_of_granularity() {
        assert!(is_valid_aad_len(0, 32));
        assert!(is_valid_aad_len(32, 32));
        assert!(is_valid_aad_len(64, 32));
        assert!(is_valid_aad_len(MAX_AAD_LEN - (MAX_AAD_LEN % 32), 32));
        assert!(is_valid_aad_len(17, 1));
        assert!(is_valid_aad_len(0, 1));
    }

    #[test]
    fn valid_aad_len_rejects_others() {
        for n in [1usize, 2, 16, 17, 31, 33, 63] {
            assert!(!is_valid_aad_len(n, 32), "n={n}");
        }
        assert!(!is_valid_aad_len(MAX_AAD_LEN + 32, 32));
        assert!(!is_valid_aad_len(MAX_AAD_LEN + 1, 1));
    }

    #[test]
    fn header_round_trip() {
        let mut buf = [0u8; HEADER_LEN];
        write_header(&mut buf, AeadAlg::AesGcm256, 64).unwrap();
        assert_eq!(buf, *b"AEAD\x03\x00\x00\x40");
        let h = read_header(&buf).unwrap();
        assert_eq!(h.alg, AeadAlg::AesGcm256);
        assert_eq!(h.aad_len, 64);
    }

    #[test]
    fn read_header_bad_magic() {
        assert_eq!(
            read_header(b"AEAd\x03\x00\x00\x00"),
            Err(CryptoError::AeadEnvelopeInvalidFormat)
        );
    }

    #[test]
    fn read_header_unsupported_alg() {
        assert_eq!(
            read_header(b"AEAD\x01\x00\x00\x00"),
            Err(CryptoError::AeadEnvelopeUnsupportedAlg)
        );
    }

    #[test]
    fn read_header_reserved_must_be_zero() {
        assert_eq!(
            read_header(b"AEAD\x03\x01\x00\x00"),
            Err(CryptoError::AeadEnvelopeInvalidFormat)
        );
    }

    #[test]
    fn read_header_bad_aad_len() {
        assert_eq!(
            read_header(b"AEAD\x03\x00\x00\x11"),
            Err(CryptoError::AeadEnvelopeInvalidAadLength)
        );
    }

    #[test]
    fn read_header_too_short() {
        assert_eq!(
            read_header(b"AEAD\x03\x00\x00"),
            Err(CryptoError::GcmBufferTooSmall)
        );
    }

    #[test]
    fn write_header_bad_aad_len() {
        let mut buf = [0u8; HEADER_LEN];
        assert_eq!(
            write_header(&mut buf, AeadAlg::AesGcm256, 17),
            Err(CryptoError::AeadEnvelopeInvalidAadLength)
        );
    }

    #[test]
    fn write_header_buf_too_small() {
        let mut buf = [0u8; HEADER_LEN - 1];
        assert_eq!(
            write_header(&mut buf, AeadAlg::AesGcm256, 0),
            Err(CryptoError::GcmBufferTooSmall)
        );
    }
}
