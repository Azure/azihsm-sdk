// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-scope and hash-algorithm wire mirrors for TBOR key-property
//! schemas.

use open_enum::open_enum;

/// Key scope (lifecycle / visibility domain) on the TBOR wire — a
/// wire-side mirror of the firmware [`HsmKeyScope`] enum
/// ([`azihsm_fw_hsm_pal_traits::HsmKeyScope`]).
///
/// The 3-bit discriminants MUST stay byte-identical to `HsmKeyScope` so
/// the two convert losslessly.  Kept as a dedicated [`open_enum`] so the
/// closed-domain PAL type stays untouched and an unrecognized
/// discriminant round-trips as `KeyScope(x)` rather than failing to
/// decode.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScope {
    /// No scope. The all-zero default carried by every MBOR-created and
    /// pre-scope (legacy) key; scope semantics do not apply.
    Unspecified = 0b000,

    /// Session-scoped key; deleted when its session closes.
    Session = 0b001,

    /// Ephemeral key; lives only for the duration of an operation and is
    /// never persisted.
    Ephemeral = 0b010,

    /// Partition-local key.
    Local = 0b011,

    /// Security-domain–scoped key.
    SecurityDomain = 0b100,

    /// Firmware-internal key.
    Internal = 0b101,
}

/// Hash algorithm selector on the TBOR wire.
///
/// The 1-byte discriminants mirror the firmware
/// [`HsmHashAlgo`](azihsm_fw_hsm_pal_traits::HsmHashAlgo) values
/// (`Sha256 = 1`, `Sha384 = 2`, `Sha512 = 3`) so the two convert
/// losslessly.  Shared across the key-property schemas: it selects both
/// the HMAC SHA variant (`HmacGenerateKey`) and the OAEP hash
/// (`UnwrapKey`).  Kept as an [`open_enum`] so an unrecognized
/// discriminant round-trips as `HashAlgo(x)` and is rejected on-device
/// rather than failing to decode.  SHA-1 is intentionally absent.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    /// SHA-256 (32-byte digest; 32-byte HMAC key / tag).
    Sha256 = 1,

    /// SHA-384 (48-byte digest; 48-byte HMAC key / tag).
    Sha384 = 2,

    /// SHA-512 (64-byte digest; 64-byte HMAC key / tag).
    Sha512 = 3,
}

/// Requested key-usage permissions on the TBOR wire — a compact 1-byte
/// bitfield carried by key-creating / key-import commands (e.g.
/// `UnwrapKey`) so the host, not the firmware, selects which operations
/// the imported/created key may perform.
///
/// The bits mirror the usage semantics of the MBOR
/// `DdiTargetKeyMetadata` flags (minus the `session`/`modifiable` bits,
/// which TBOR carries out of band via the key scope): `sign`+`verify`
/// and `encrypt`+`decrypt` are matched pairs, and each handler enforces
/// which usage(s) are valid for the key's class.  Sent inline as a raw
/// `u8` (`#[tbor(U8)]`); an out-of-range/invalid combination is rejected
/// on-device rather than failing to decode.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyUsage(pub u8);

impl KeyUsage {
    /// Key may encrypt.
    pub const ENCRYPT: u8 = 1 << 0;
    /// Key may decrypt.
    pub const DECRYPT: u8 = 1 << 1;
    /// Key may sign / compute a MAC.
    pub const SIGN: u8 = 1 << 2;
    /// Key may verify a signature / MAC.
    pub const VERIFY: u8 = 1 << 3;
    /// Key may derive other keys.
    pub const DERIVE: u8 = 1 << 4;
    /// Key may wrap other keys.
    pub const WRAP: u8 = 1 << 5;
    /// Key may unwrap other keys.
    pub const UNWRAP: u8 = 1 << 6;

    /// Build a `KeyUsage` from its raw wire bits.
    #[inline]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The raw wire bits.
    #[inline]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `flag` (one of the `KeyUsage::*` bit constants) is set.
    #[inline]
    pub const fn has(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    /// `encrypt` bit.
    #[inline]
    pub const fn encrypt(self) -> bool {
        self.has(Self::ENCRYPT)
    }

    /// `decrypt` bit.
    #[inline]
    pub const fn decrypt(self) -> bool {
        self.has(Self::DECRYPT)
    }

    /// `sign` bit.
    #[inline]
    pub const fn sign(self) -> bool {
        self.has(Self::SIGN)
    }

    /// `verify` bit.
    #[inline]
    pub const fn verify(self) -> bool {
        self.has(Self::VERIFY)
    }

    /// `derive` bit.
    #[inline]
    pub const fn derive(self) -> bool {
        self.has(Self::DERIVE)
    }

    /// `wrap` bit.
    #[inline]
    pub const fn wrap(self) -> bool {
        self.has(Self::WRAP)
    }

    /// `unwrap` bit.
    #[inline]
    pub const fn unwrap(self) -> bool {
        self.has(Self::UNWRAP)
    }
}

/// Derived-key type selector for the KDF commands (`HkdfDerive`,
/// `ConcatKdfDerive`) on the TBOR wire.
///
/// The 1-byte discriminants mirror the KDF-eligible subset of the MBOR
/// `DdiKeyType` values (`Aes128 = 10` … `VarHmac512 = 32`) so the two
/// convert losslessly.  Kept as an [`open_enum`] so an unrecognized
/// discriminant round-trips as `KdfKeyType(x)` and is rejected on-device
/// rather than failing to decode.  Only symmetric outputs are derivable:
/// the fixed-length `HmacSha*` outputs derive the hash's natural key
/// length, while the `VarHmac*` outputs take an explicit `key_length`.
#[repr(u8)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfKeyType {
    /// AES-128 (16-byte key).
    Aes128 = 10,
    /// AES-192 (24-byte key).
    Aes192 = 11,
    /// AES-256 (32-byte key).
    Aes256 = 12,

    /// HMAC-SHA-256 key, fixed 32-byte length.
    HmacSha256 = 25,
    /// HMAC-SHA-384 key, fixed 48-byte length.
    HmacSha384 = 26,
    /// HMAC-SHA-512 key, fixed 64-byte length.
    HmacSha512 = 27,

    /// Variable-length HMAC-SHA-256 key (`key_length` in 32..=64).
    VarHmac256 = 30,
    /// Variable-length HMAC-SHA-384 key (`key_length` in 48..=128).
    VarHmac384 = 31,
    /// Variable-length HMAC-SHA-512 key (`key_length` in 64..=128).
    VarHmac512 = 32,
}
