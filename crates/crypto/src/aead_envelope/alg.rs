// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AEAD algorithm registry.
//!
//! The [`AeadAlg`] discriminant occupies the second byte of every
//! envelope header and selects every per-algorithm parameter (key
//! length, IV length, tag length, AAD-length granularity).
//!
//! v1 supports exactly one algorithm: AES-256-GCM (`0x03`). Future
//! algorithms can be added without a wire-format break by reserving
//! a new discriminant and routing it in the dispatcher.

use super::format::HEADER_LEN;
use crate::CryptoError;

/// AEAD algorithm registry.
///
/// Stable u8 discriminants — these values are part of the wire
/// format and MUST NOT change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u8)]
pub enum AeadAlg {
    /// AES-256-GCM (96-bit IV, 128-bit tag). The only variant
    /// supported in v1.
    AesGcm256 = 0x03,
}

impl AeadAlg {
    /// Parse a wire-format `alg` byte. Returns
    /// [`CryptoError::AeadEnvelopeUnsupportedAlg`] for any value
    /// not recognised in this build.
    pub const fn from_u8(b: u8) -> Result<Self, CryptoError> {
        match b {
            0x03 => Ok(Self::AesGcm256),
            _ => Err(CryptoError::AeadEnvelopeUnsupportedAlg),
        }
    }

    /// Wire-format `alg` byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Required key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesGcm256 => 32,
        }
    }

    /// Required IV length in bytes.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::AesGcm256 => 12,
        }
    }

    /// Tag length in bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::AesGcm256 => 16,
        }
    }

    /// AAD-length granularity in bytes. `aad_len` must be `0` or a
    /// multiple of this value.
    ///
    /// For GCM the value is `32`, mirroring the fw side's
    /// hardware-driven constraint so envelopes produced by either
    /// side share an identical wire layout.
    pub const fn aad_granularity(self) -> usize {
        match self {
            Self::AesGcm256 => 32,
        }
    }

    /// Total envelope length for the given plaintext and AAD
    /// lengths: `HEADER_LEN + iv_len + aad_len + pt_len + tag_len`.
    ///
    /// Uses `saturating_add` to avoid overflow panics on adversarial
    /// inputs; the caller is responsible for separately validating
    /// `aad_len <= MAX_AAD_LEN`.
    pub const fn envelope_len(self, pt_len: usize, aad_len: usize) -> usize {
        HEADER_LEN
            .saturating_add(self.iv_len())
            .saturating_add(aad_len)
            .saturating_add(pt_len)
            .saturating_add(self.tag_len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn aes256gcm_parameters() {
        let a = AeadAlg::AesGcm256;
        assert_eq!(a.as_u8(), 0x03);
        assert_eq!(a.key_len(), 32);
        assert_eq!(a.iv_len(), 12);
        assert_eq!(a.tag_len(), 16);
        assert_eq!(a.aad_granularity(), 32);
        assert_eq!(a.envelope_len(0, 0), 8 + 12 + 16);
        // 8 + 12 + 32 (aad) + 17 (pt) + 16 = 85
        assert_eq!(a.envelope_len(17, 32), 8 + 12 + 32 + 17 + 16);
    }

    #[test]
    fn from_u8_round_trip() {
        assert_eq!(AeadAlg::from_u8(0x03).unwrap(), AeadAlg::AesGcm256);
    }

    #[test]
    fn from_u8_rejects_unknown() {
        for b in [0x00u8, 0x01, 0x02, 0x04, 0xFF] {
            assert!(matches!(
                AeadAlg::from_u8(b),
                Err(CryptoError::AeadEnvelopeUnsupportedAlg)
            ));
        }
    }
}
