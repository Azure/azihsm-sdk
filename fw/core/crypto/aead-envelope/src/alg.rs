// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Supported AEAD algorithms and their fixed sizing.
//!
//! v1 supports only AES-256-GCM. Other discriminants are reserved
//! for future variants and listed in the registry below; they are
//! not currently accepted by [`AeadAlg::from_u8`].
//!
//! | `alg` byte | Variant                  | Status                          |
//! |------------|--------------------------|---------------------------------|
//! | `0x01`     | AES-128-GCM              | reserved (not implemented)      |
//! | `0x02`     | AES-192-GCM              | reserved (not implemented)      |
//! | `0x03`     | AES-256-GCM              | **v1 — the only supported alg** |
//! | `0x11`–`0x13` | AES-CBC-HMAC-SHA-2 family | reserved (not implemented)   |

/// AEAD algorithms supported by the envelope format.
///
/// The discriminant value of each variant is the byte serialized
/// into the envelope's `alg` field. The numbering aligns with the
/// reserved registry documented at the [module level](self).
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    /// AES-256-GCM with a 96-bit nonce and 128-bit tag (NIST
    /// SP 800-38D). Wire byte: `0x03`.
    AesGcm256 = 0x03,
}

/// AES-GCM IV length in bytes (NIST-recommended 96-bit nonce).
const GCM_IV_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes.
const GCM_TAG_LEN: usize = 16;

/// AES-256 key length in bytes.
const AES_256_KEY_LEN: usize = 32;

impl AeadAlg {
    /// Decode an `alg` byte from the envelope header.
    ///
    /// Returns `None` for any byte that does not correspond to a
    /// variant supported by this crate version. Reserved registry
    /// entries (`0x01`, `0x02`, `0x11`..=`0x13`) are also rejected
    /// in v1.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(Self::AesGcm256),
            _ => None,
        }
    }

    /// Serialized wire byte for this algorithm.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Required key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesGcm256 => AES_256_KEY_LEN,
        }
    }

    /// Required IV length in bytes.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::AesGcm256 => GCM_IV_LEN,
        }
    }

    /// Authentication tag length in bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::AesGcm256 => GCM_TAG_LEN,
        }
    }

    /// AAD-length granularity in bytes. `aad_len` must be `0` or a
    /// multiple of this value at [`seal`](crate::seal) /
    /// [`open`](crate::open).
    ///
    /// AES-256-GCM uses `32` — the ocelot BCP `[padded_AAD | text]`
    /// hardware layout requires AAD padding to a 32-byte boundary,
    /// and constraining the wire `aad_len` to a multiple of 32
    /// makes that padding a no-op (wire layout = DMA layout).
    /// Future algorithms with no alignment requirement (e.g.
    /// ChaCha20-Poly1305 on a software PAL) would return `1`.
    pub const fn aad_granularity(self) -> usize {
        match self {
            Self::AesGcm256 => 32,
        }
    }

    /// Total envelope length for the given plaintext / AAD lengths.
    ///
    /// `= HEADER_LEN + iv_len + aad_len + pt_len + tag_len`.
    ///
    /// Saturates at [`usize::MAX`] on overflow; callers that pass
    /// validated sizes never observe saturation.
    pub const fn envelope_len(self, pt_len: usize, aad_len: usize) -> usize {
        // saturating_add is the only const-stable saturating op we
        // need; overflow is unreachable in practice (header sizes are
        // tiny) but we still avoid wrapping for safety.
        crate::format::HEADER_LEN
            .saturating_add(self.iv_len())
            .saturating_add(aad_len)
            .saturating_add(pt_len)
            .saturating_add(self.tag_len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_accepts_only_0x03() {
        assert_eq!(AeadAlg::from_u8(0x03), Some(AeadAlg::AesGcm256));
        for v in 0u8..=0xFF {
            if v == 0x03 {
                continue;
            }
            assert_eq!(AeadAlg::from_u8(v), None, "v=0x{v:02x}");
        }
    }

    #[test]
    fn sizing_constants() {
        let a = AeadAlg::AesGcm256;
        assert_eq!(a.key_len(), 32);
        assert_eq!(a.iv_len(), 12);
        assert_eq!(a.tag_len(), 16);
        assert_eq!(a.aad_granularity(), 32);
        // 4 (header) + 12 (iv) + 0 (aad) + 0 (pt) + 16 (tag) = 32
        assert_eq!(a.envelope_len(0, 0), 36);
        // 8 + 12 + 32 (aad) + 17 (pt) + 16 = 85
        assert_eq!(a.envelope_len(17, 32), 85);
    }

    #[test]
    fn as_u8_round_trip() {
        assert_eq!(AeadAlg::AesGcm256.as_u8(), 0x03);
        assert_eq!(
            AeadAlg::from_u8(AeadAlg::AesGcm256.as_u8()),
            Some(AeadAlg::AesGcm256)
        );
    }
}
