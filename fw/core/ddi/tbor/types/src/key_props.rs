// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Key-scope wire mirror for TBOR key-property schemas.

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
