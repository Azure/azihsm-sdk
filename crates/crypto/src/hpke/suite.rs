// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE ciphersuite definitions and per-suite constants.
//!
//! Six ciphersuites are exposed via [`HpkeSuite`]. Three are RFC 9180
//! standard combinations (DHKEM(P-N) + HKDF + AES-256-GCM); the other
//! three substitute AES-256-CBC + HMAC for the AEAD step using a
//! private-use AEAD identifier (`0xFFFF`) and a FIPS-compliant key
//! sizing scheme. The same private-use ID is used by the firmware HPKE
//! implementation in `fw/core/crypto/hpke`.
//!
//! # Wire formats (host)
//!
//! Public keys and the encapsulated key (`enc`) are SEC1 uncompressed
//! (`0x04 ‖ x ‖ y`) for RFC 9180 interoperability. Private keys are
//! raw big-endian scalars (no PKCS#8 wrapping).
//!
//! | Suite                          | `Npk = Nenc` | `Nsk` | `Nsecret = Nh` | `Ndh` |
//! |--------------------------------|--------------|-------|----------------|-------|
//! | DHKEM(P-256) + HKDF-SHA-256    | 65           | 32    | 32             | 32    |
//! | DHKEM(P-384) + HKDF-SHA-384    | 97           | 48    | 48             | 48    |
//! | DHKEM(P-521) + HKDF-SHA-512    | 133          | 66    | 64             | 66    |
//!
//! `Nsecret` is the KEM shared-secret length and equals `Nh`. `Ndh`
//! is the raw ECDH x-coordinate (RFC 9180 §7.1.1) — note that for
//! P-521 it is 66, not 64.
//!
//! # CBC-HMAC AEAD key layout
//!
//! The CBC variants use the FIPS-compliant key sizing scheme defined
//! by the firmware HPKE crate:
//!
//! ```text
//! key       = MAC_KEY[Nh] ‖ ENC_KEY[32]
//! tag_len   = Nh             (full HMAC output, no truncation)
//! mac_input = aad ‖ iv ‖ ciphertext ‖ I2OSP(aad.len() * 8, 8)
//! ```

use crate::EccCurve;
use crate::HashAlgo;

// =============================================================================
// HpkeSuite enum
// =============================================================================

/// HPKE ciphersuite.
///
/// All suites use AES-256. The CBC variants use AES-256-CBC + HMAC
/// with FIPS-compliant MAC key lengths (= full hash output, per
/// SP 800-107).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum HpkeSuite {
    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
    DHKemP256Sha256AesGcm256,

    /// DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-CBC-HMAC-SHA256.
    DHKemP256Sha256Aes256Cbc,

    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
    DHKemP384Sha384AesGcm256,

    /// DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-CBC-HMAC-SHA384.
    DHKemP384Sha384Aes256Cbc,

    /// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
    DHKemP521Sha512AesGcm256,

    /// DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-CBC-HMAC-SHA512.
    DHKemP521Sha512Aes256Cbc,
}

// =============================================================================
// Internal KEM table
// =============================================================================

#[derive(Clone, Copy)]
struct KemEntry {
    kem_id: u16,
    kdf_id: u16,
    curve: EccCurve,
    nh: usize,
    nsk: usize,
    ndh: usize,
}

#[derive(Clone, Copy)]
enum KemKind {
    P256 = 0,
    P384 = 1,
    P521 = 2,
}

const KEM_TABLE: [KemEntry; 3] = [
    KemEntry {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        curve: EccCurve::P256,
        nh: 32,
        nsk: 32,
        ndh: 32,
    },
    KemEntry {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        curve: EccCurve::P384,
        nh: 48,
        nsk: 48,
        ndh: 48,
    },
    KemEntry {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        curve: EccCurve::P521,
        nh: 64,
        nsk: 66,
        ndh: 66,
    },
];

const AEAD_ID_GCM: u16 = 0x0002;
const AEAD_ID_CBC: u16 = 0xFFFF;
const AES256_KEY_LEN: usize = 32;
const CBC_IV_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const SEC1_UNCOMPRESSED_PREFIX_LEN: usize = 1;

// =============================================================================
// HpkeSuite accessors
// =============================================================================

impl HpkeSuite {
    const fn parts(&self) -> (KemKind, bool) {
        match self {
            Self::DHKemP256Sha256AesGcm256 => (KemKind::P256, false),
            Self::DHKemP256Sha256Aes256Cbc => (KemKind::P256, true),
            Self::DHKemP384Sha384AesGcm256 => (KemKind::P384, false),
            Self::DHKemP384Sha384Aes256Cbc => (KemKind::P384, true),
            Self::DHKemP521Sha512AesGcm256 => (KemKind::P521, false),
            Self::DHKemP521Sha512Aes256Cbc => (KemKind::P521, true),
        }
    }

    const fn entry(&self) -> &'static KemEntry {
        let (kind, _) = self.parts();
        &KEM_TABLE[kind as usize]
    }

    /// Returns the IANA KEM identifier (RFC 9180 §7.1).
    pub const fn kem_id(&self) -> u16 {
        self.entry().kem_id
    }

    /// Returns the IANA KDF identifier (RFC 9180 §7.2).
    pub const fn kdf_id(&self) -> u16 {
        self.entry().kdf_id
    }

    /// Returns the IANA AEAD identifier (RFC 9180 §7.3, plus the
    /// private-use value for the CBC variants).
    pub const fn aead_id(&self) -> u16 {
        if self.is_cbc() {
            AEAD_ID_CBC
        } else {
            AEAD_ID_GCM
        }
    }

    /// `true` for the AES-256-CBC + HMAC variants, `false` for GCM.
    pub const fn is_cbc(&self) -> bool {
        let (_, is_cbc) = self.parts();
        is_cbc
    }

    /// NIST curve used by the KEM.
    pub const fn kem_curve(&self) -> EccCurve {
        self.entry().curve
    }

    /// Hash algorithm used by the KDF, KEM, and CBC-HMAC AEAD.
    pub fn kdf_hash(&self) -> HashAlgo {
        match self.entry().nh {
            32 => HashAlgo::sha256(),
            48 => HashAlgo::sha384(),
            _ => HashAlgo::sha512(),
        }
    }

    /// AEAD key length in bytes (`Nk`).
    ///
    /// * GCM: 32 bytes (AES-256 key).
    /// * CBC: `mac_key_len + 32` bytes (`MAC_KEY ‖ ENC_KEY`).
    pub const fn nk(&self) -> usize {
        if self.is_cbc() {
            self.cbc_mac_key_len() + AES256_KEY_LEN
        } else {
            AES256_KEY_LEN
        }
    }

    /// AEAD nonce / IV length in bytes (`Nn`).
    pub const fn nn(&self) -> usize {
        if self.is_cbc() {
            CBC_IV_LEN
        } else {
            GCM_NONCE_LEN
        }
    }

    /// KDF hash output length in bytes (`Nh`).
    pub const fn nh(&self) -> usize {
        self.entry().nh
    }

    /// AEAD tag length in bytes (`Nt`).
    ///
    /// * GCM: always 16.
    /// * CBC: full HMAC output (`Nh`) — wire-compatible with the
    ///   firmware HPKE crate.
    pub const fn nt(&self) -> usize {
        if self.is_cbc() {
            self.nh()
        } else {
            GCM_TAG_LEN
        }
    }

    /// KEM public-key length in bytes (`Npk = Nenc`), SEC1 uncompressed.
    pub const fn npk(&self) -> usize {
        SEC1_UNCOMPRESSED_PREFIX_LEN + 2 * self.entry().nsk
    }

    /// KEM encapsulated-key length in bytes (`Nenc = Npk`).
    pub const fn nenc(&self) -> usize {
        self.npk()
    }

    /// KEM private-key length in bytes (`Nsk`, raw scalar).
    pub const fn nsk(&self) -> usize {
        self.entry().nsk
    }

    /// KEM shared-secret length in bytes (`Nsecret = Nh`).
    pub const fn nsecret(&self) -> usize {
        self.nh()
    }

    /// Raw ECDH shared-secret length in bytes (`Ndh`, curve byte
    /// size — note 66 for P-521, not 64).
    pub const fn ndh(&self) -> usize {
        self.entry().ndh
    }

    /// CBC-HMAC MAC key length = full hash output length.
    pub const fn cbc_mac_key_len(&self) -> usize {
        self.nh()
    }

    /// CBC-HMAC encryption-key length (always 32 for AES-256).
    pub const fn cbc_enc_key_len(&self) -> usize {
        AES256_KEY_LEN
    }

    /// KEM suite identifier: `concat("KEM", I2OSP(kem_id, 2))` = 5 bytes.
    pub const fn kem_suite_id(&self) -> [u8; 5] {
        let id = self.kem_id().to_be_bytes();
        [b'K', b'E', b'M', id[0], id[1]]
    }

    /// HPKE suite identifier: `concat("HPKE", kem_id, kdf_id, aead_id)`
    /// = 10 bytes.
    pub const fn hpke_suite_id(&self) -> [u8; 10] {
        let kem = self.kem_id().to_be_bytes();
        let kdf = self.kdf_id().to_be_bytes();
        let aead = self.aead_id().to_be_bytes();
        [
            b'H', b'P', b'K', b'E', kem[0], kem[1], kdf[0], kdf[1], aead[0], aead[1],
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sizes() {
        let s = HpkeSuite::DHKemP256Sha256AesGcm256;
        assert_eq!(s.npk(), 65);
        assert_eq!(s.nsk(), 32);
        assert_eq!(s.nh(), 32);
        assert_eq!(s.nk(), 32);
        assert_eq!(s.nn(), 12);
        assert_eq!(s.nt(), 16);
        assert_eq!(s.ndh(), 32);
        assert_eq!(s.nsecret(), 32);

        let s = HpkeSuite::DHKemP521Sha512AesGcm256;
        assert_eq!(s.npk(), 133);
        assert_eq!(s.nsk(), 66);
        assert_eq!(s.nh(), 64);
        assert_eq!(s.nsecret(), 64);
        assert_eq!(s.ndh(), 66);

        let s = HpkeSuite::DHKemP384Sha384Aes256Cbc;
        assert_eq!(s.nk(), 48 + 32);
        assert_eq!(s.nn(), 16);
        assert_eq!(s.nt(), 48); // full HMAC-SHA-384 output
        assert_eq!(s.aead_id(), 0xFFFF);
    }

    #[test]
    fn suite_ids() {
        let s = HpkeSuite::DHKemP256Sha256AesGcm256;
        assert_eq!(s.kem_suite_id(), *b"KEM\x00\x10");
        assert_eq!(s.hpke_suite_id(), *b"HPKE\x00\x10\x00\x01\x00\x02");
    }
}
