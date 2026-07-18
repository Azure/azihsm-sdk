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
