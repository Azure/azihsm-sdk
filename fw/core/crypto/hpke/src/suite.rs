// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HPKE ciphersuite definitions and per-suite size constants.
//!
//! Six ciphersuites are exposed as a single [`HpkeSuite`] enum. Three
//! of them are RFC 9180 standard combinations (DHKEM(P-N) + HKDF + AES-
//! 256-GCM); the other three substitute AES-256-CBC + HMAC for the
//! AEAD step using a private-use AEAD identifier (`0xFFFF`) and a
//! FIPS-compliant key sizing scheme.
//!
//! ## CBC-HMAC key layout
//!
//! For the CBC variants the AEAD key concatenates the MAC key (size =
//! hash output length per SP 800-107) and the AES encryption key
//! (always 32 bytes for AES-256):
//!
//! | Suite      | `MAC_KEY` | `ENC_KEY` | Total `Nk` | Tag `Nt` |
//! |------------|-----------|-----------|------------|----------|
//! | P-256/CBC  | 32        | 32        | 64         | 32       |
//! | P-384/CBC  | 48        | 32        | 80         | 48       |
//! | P-521/CBC  | 64        | 32        | 96         | 64       |
//!
//! The tag is the full HMAC output (no truncation).
//!
//! ## Internal representation
//!
//! Every per-suite quantity is derived from two orthogonal selectors —
//! the [`KemKind`] (curve / hash family) and an `is_cbc` flag. This
//! avoids the original `match` ladder in every accessor and keeps the
//! per-curve constants in a single [`KEM_TABLE`] entry.

use azihsm_fw_hsm_pal_traits::HsmEccCurve;
use azihsm_fw_hsm_pal_traits::HsmHashAlgo;

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

/// Per-curve KEM/KDF parameters. The CBC vs GCM differences are
/// handled separately in [`HpkeSuite`] accessors.
#[derive(Clone, Copy)]
struct KemEntry {
    /// IANA KEM identifier (RFC 9180 §7.1).
    kem_id: u16,
    /// IANA KDF identifier (RFC 9180 §7.2).
    kdf_id: u16,
    /// Underlying NIST curve.
    curve: HsmEccCurve,
    /// HKDF / KEM hash algorithm.
    hash: HsmHashAlgo,
    /// Hash output length in bytes (`Nh`).
    nh: usize,
    /// HSM-format public-key length in bytes (`Npk = Nenc`,
    /// `x ‖ y` with HSM 4-byte alignment for P-521).
    npk: usize,
    /// HSM-format private-key length in bytes (`Nsk`).
    nsk: usize,
    /// Raw ECDH shared-secret length in bytes (`Ndh = curve byte size`).
    ndh: usize,
}

/// Curve-family selector. The integer value is the index into
/// [`KEM_TABLE`].
#[derive(Clone, Copy)]
enum KemKind {
    P256 = 0,
    P384 = 1,
    P521 = 2,
}

/// One entry per [`KemKind`].
///
/// `npk` is the SEC1 uncompressed wire size (`1 + 2 * Nsk` per
/// RFC 9180 §7.1.1) used in `kem_context` and on the wire. The
/// PAL-native size (raw `x ‖ y`, LE) is `npk_pal = 2 * nsk` derived
/// at use-site; see [`HpkeSuite::npk_pal`].
///
/// P-521 entry is left at the legacy PAL-padded value and is not
/// RFC 9180 compliant — that suite is not currently supported.
const KEM_TABLE: [KemEntry; 3] = [
    KemEntry {
        kem_id: 0x0010,
        kdf_id: 0x0001,
        curve: HsmEccCurve::P256,
        hash: HsmHashAlgo::Sha256,
        nh: 32,
        npk: 65,
        nsk: 32,
        ndh: 32,
    },
    KemEntry {
        kem_id: 0x0011,
        kdf_id: 0x0002,
        curve: HsmEccCurve::P384,
        hash: HsmHashAlgo::Sha384,
        nh: 48,
        npk: 97,
        nsk: 48,
        ndh: 48,
    },
    KemEntry {
        kem_id: 0x0012,
        kdf_id: 0x0003,
        curve: HsmEccCurve::P521,
        hash: HsmHashAlgo::Sha512,
        nh: 64,
        // P-521 is unsupported: PAL uses 4-byte aligned coords (68 B
        // each) which conflicts with RFC 9180 P-521 (66 B each).
        npk: 136,
        nsk: 68,
        ndh: 66,
    },
];

/// IANA AEAD identifier for AES-256-GCM (RFC 9180 §7.3).
const AEAD_ID_GCM: u16 = 0x0002;

/// Private-use AEAD identifier this crate assigns to AES-256-CBC + HMAC.
const AEAD_ID_CBC: u16 = 0xFFFF;

/// AES-256 encryption key length used by every CBC suite.
const AES256_KEY_LEN: usize = 32;

/// AES-CBC IV / GCM nonce sizes.
const CBC_IV_LEN: usize = 16;
const GCM_NONCE_LEN: usize = 12;

/// AES-256-GCM tag size.
const GCM_TAG_LEN: usize = 16;

// =============================================================================
// HpkeSuite accessors
// =============================================================================

impl HpkeSuite {
    /// Decompose the suite into its `(KemKind, is_cbc)` selector pair.
    ///
    /// # Returns
    /// * `(kind, is_cbc)` — `kind` indexes into [`KEM_TABLE`] and
    ///   `is_cbc` selects the AEAD variant.
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

    /// Borrow the per-curve [`KemEntry`] backing this suite.
    const fn entry(&self) -> &'static KemEntry {
        let (kind, _) = self.parts();
        &KEM_TABLE[kind as usize]
    }

    // ── IANA identifiers ──────────────────────────────────────────

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

    // ── Crypto algorithm selectors ────────────────────────────────

    /// NIST curve used by the KEM.
    pub const fn kem_curve(&self) -> HsmEccCurve {
        self.entry().curve
    }

    /// Hash algorithm used by KEM, KDF, and AEAD HMAC.
    pub const fn kdf_hash(&self) -> HsmHashAlgo {
        self.entry().hash
    }

    /// Hash algorithm used by the KEM (always equal to [`Self::kdf_hash`]).
    pub const fn kem_hash(&self) -> HsmHashAlgo {
        self.kdf_hash()
    }

    /// Hash algorithm used by the CBC-HMAC AEAD (always equal to
    /// [`Self::kdf_hash`]).
    pub const fn aead_hash(&self) -> HsmHashAlgo {
        self.kdf_hash()
    }

    // ── Size constants ────────────────────────────────────────────

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
    ///
    /// * GCM: 12 (96-bit IV).
    /// * CBC: 16 (one AES block).
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
    /// * CBC: full HMAC output (`Nh`), no truncation.
    pub const fn nt(&self) -> usize {
        if self.is_cbc() {
            self.nh()
        } else {
            GCM_TAG_LEN
        }
    }

    /// KEM public-key length in bytes (`Npk = Nenc`).
    ///
    /// SEC1 uncompressed (`0x04 ‖ X ‖ Y`, big-endian) per
    /// RFC 9180 §7.1.1. The on-the-wire / `kem_context` encoding.
    ///
    /// **P-521 unsupported.** The HSM PAL pads P-521 coords to 4-byte
    /// alignment (68 B each) which conflicts with the RFC 9180 P-521
    /// encoding (66 B each). P-521 HPKE is not currently usable; the
    /// per-suite constant below is left at the legacy padded value
    /// so callers that don't exercise P-521 keep compiling.
    pub const fn npk(&self) -> usize {
        self.entry().npk
    }

    /// PAL-native KEM public-key length in bytes
    /// (`2 * Nsk_pal`, no SEC1 prefix, little-endian coords).
    ///
    /// Used only inside this crate to size buffers passed to / from
    /// the [`HsmCrypto::ecc_gen_keypair`] / [`HsmCrypto::ecdh_derive`]
    /// PAL entry points, which traffic in the HSM-native LE coord
    /// format throughout. See [`Self::npk`] for the wire-format size.
    pub const fn npk_pal(&self) -> usize {
        2 * self.entry().nsk
    }

    /// KEM encapsulated-key length in bytes (`Nenc`). Same as
    /// [`Self::npk`] for DHKEM.
    pub const fn nenc(&self) -> usize {
        self.npk()
    }

    /// KEM private-key length in bytes (`Nsk`). P-521 uses 68 bytes
    /// (4-byte aligned HSM wire format).
    pub const fn nsk(&self) -> usize {
        self.entry().nsk
    }

    /// KEM shared-secret length in bytes (`Nsecret = Nh`).
    pub const fn nsecret(&self) -> usize {
        self.nh()
    }

    /// Raw ECDH shared-secret length in bytes (`Ndh`).
    ///
    /// This is the curve byte size, NOT the HSM-padded size. P-521
    /// raw x-coordinate is 66 bytes.
    pub const fn ndh(&self) -> usize {
        self.entry().ndh
    }

    /// CBC-HMAC MAC key length = full hash output length (FIPS
    /// SP 800-107 compliant).
    pub const fn cbc_mac_key_len(&self) -> usize {
        self.nh()
    }

    /// CBC-HMAC encryption-key length (always 32 for AES-256).
    pub const fn cbc_enc_key_len(&self) -> usize {
        AES256_KEY_LEN
    }

    // ── Suite-id construction ─────────────────────────────────────

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
