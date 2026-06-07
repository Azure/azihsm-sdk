// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition policy ([`PartPolicy`]) byte layout.
//!
//! Canonical, single source of truth.  This crate is the DDI types
//! crate and must not depend on the firmware crate
//! (`azihsm_fw_hsm_core`) or on firmware-only primitives like
//! `DmaBuf` / `HsmError`.  The validation/parser surface
//! (`from_bytes(&DmaBuf) -> HsmResult<&PartPolicy>`) that consumes
//! those firmware primitives lives in
//! `fw/core/lib/src/ddi/tbor/policy.rs` as a thin free function over
//! the types here.
//!
//! Layout discipline:
//!
//! * Every multi-byte scalar is stored as a little-endian byte array
//!   (`[u8; 2]` instead of `u16`) to keep all structs alignment-1.
//! * `#[repr(C)]` + zerocopy [`TryFromBytes`] / [`IntoBytes`] /
//!   [`Immutable`] / [`KnownLayout`] derives reject any padding /
//!   alignment drift at compile time.
//! * The `const _: () = assert!(...)` blocks at the bottom pin
//!   absolute byte sizes as a belt-and-braces check.

use open_enum::open_enum;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

/// Maximum key length for [`PolicyPubKey::data`] (bytes).
///
/// Sized for an uncompressed P-384 SEC1 point (`0x04 ‖ X ‖ Y`).
pub const POLICY_MAX_KEY_LEN: usize = 97;

/// Caller-provided opaque info bytes embedded in [`PartPolicy::info`].
pub const POLICY_INFO_LEN: usize = 64;

/// Supported [`PolicyVer::major`] value.  Parsers must reject any
/// other major version.
pub const POLICY_VERSION_MAJOR: u8 = 1;

/// Discriminants for [`PolicyPubKey::kind`].
///
/// Stored in the wire layout as little-endian `[u8; 2]`.  The
/// open-enum form keeps the type forward-compatible: a future spec
/// value gets a new associated `pub const` without breaking
/// exhaustive matches in older code (which already handle the
/// unknown-discriminant branch via the `_` arm).
#[repr(u16)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKeyKind {
    /// ECC P-384 public key.
    Ecc384 = 0,
}

/// Two-byte policy version (`major.minor`).
///
/// Layout (alignment 1, size 2 B): `major(1) ‖ minor(1)`.
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PolicyVer {
    /// Major version number.  Must equal [`POLICY_VERSION_MAJOR`].
    pub major: u8,

    /// Minor version number.  Any value accepted (forward-compat).
    pub minor: u8,
}

/// POTA public key embedded in [`PartPolicy`].
///
/// Layout (alignment 1, size 101 B): `kind(2 LE) ‖ len(2 LE) ‖ data(97)`.
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PolicyPubKey {
    /// [`PolicyKeyKind`] discriminant, little-endian.
    pub kind: [u8; 2],

    /// Active prefix length of `data` (`0..=POLICY_MAX_KEY_LEN`),
    /// little-endian.  For `Ecc384` must equal
    /// [`POLICY_MAX_KEY_LEN`].
    pub len: [u8; 2],

    /// Key bytes; only the first `len` bytes are meaningful.
    pub data: [u8; POLICY_MAX_KEY_LEN],
}

/// Partition policy as it appears on the `PartInit` wire and in PAL
/// persistence.
///
/// Layout (alignment 1, size 167 B):
///
/// | Field          | Offset | Size |
/// |----------------|--------|------|
/// | `version`      | 0      | 2    |
/// | `pota_pub_key` | 2      | 101  |
/// | `info`         | 103    | 64   |
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PartPolicy {
    /// Policy version (major.minor).
    pub version: PolicyVer,

    /// POTA public key bound to this partition.
    pub pota_pub_key: PolicyPubKey,

    /// Caller-provided opaque info bound into the partition's
    /// attested state.
    pub info: [u8; POLICY_INFO_LEN],
}

/// Byte size of [`PartPolicy`] in its on-wire / on-disk layout.
///
/// Used by the [`crate::TborPartInitReq`] schema as the `len`
/// constant for its `part_policy` slice.  The `const _` assertions
/// below pin the value so any layout drift fails the build instead
/// of silently changing the wire size.
pub const PART_POLICY_LEN: usize = core::mem::size_of::<PartPolicy>();

const _: () = assert!(PART_POLICY_LEN == 167);
const _: () = assert!(core::mem::align_of::<PartPolicy>() == 1);
const _: () = assert!(core::mem::size_of::<PolicyPubKey>() == 101);
const _: () = assert!(core::mem::size_of::<PolicyVer>() == 2);

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical byte fixture — `version 1.0`, `Ecc384` POTA key,
    /// `info` filled with `0xAB`.  Pinned so any layout-affecting
    /// change trips this test.
    fn known_good_bytes() -> [u8; PART_POLICY_LEN] {
        let mut bytes = [0u8; PART_POLICY_LEN];
        // version: 1.0
        bytes[0] = 1;
        bytes[1] = 0;
        // pota_pub_key.kind = Ecc384 = 0 (LE u16 of zero)
        bytes[2] = 0;
        bytes[3] = 0;
        // pota_pub_key.len = 97 (LE u16)
        bytes[4] = 97;
        bytes[5] = 0;
        // pota_pub_key.data[0] = 0x04 (SEC1 uncompressed tag)
        bytes[6] = 0x04;
        // pota_pub_key.data[1..97] = 0x11, 0x12, ... (X then Y;
        // values not validated — content is opaque past data[0])
        for (i, b) in bytes[7..7 + 96].iter_mut().enumerate() {
            *b = (0x10 + (i as u8)) | 0x80;
        }
        // info[..] @ offset 103..167 = 0xAB
        for b in bytes[103..167].iter_mut() {
            *b = 0xAB;
        }
        bytes
    }

    #[test]
    fn known_good_bytes_parses() {
        let bytes = known_good_bytes();
        let policy = PartPolicy::try_ref_from_bytes(&bytes).expect("parse");
        assert_eq!(policy.version.major, 1);
        assert_eq!(policy.version.minor, 0);
        assert_eq!(
            PolicyKeyKind(u16::from_le_bytes(policy.pota_pub_key.kind)),
            PolicyKeyKind::Ecc384,
        );
        assert_eq!(u16::from_le_bytes(policy.pota_pub_key.len), 97);
        assert_eq!(policy.pota_pub_key.data[0], 0x04);
        assert!(policy.info.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn round_trip_known_good_bytes() {
        let bytes = known_good_bytes();
        let policy = PartPolicy::try_ref_from_bytes(&bytes).expect("known-good bytes parse");
        let serialised = IntoBytes::as_bytes(policy);
        assert_eq!(serialised, &bytes);
    }

    #[test]
    fn wrong_length_rejected_by_try_from_bytes() {
        let too_short = [0u8; PART_POLICY_LEN - 1];
        assert!(PartPolicy::try_ref_from_bytes(&too_short).is_err());
        let too_long = [0u8; PART_POLICY_LEN + 1];
        assert!(PartPolicy::try_ref_from_bytes(&too_long).is_err());
    }

    #[test]
    fn part_policy_len_pin() {
        assert_eq!(PART_POLICY_LEN, 167);
    }

    #[test]
    fn open_enum_unknown_kind_is_representable() {
        // Forward-compat smoke: a future spec value (e.g. 0x0007)
        // round-trips through the open enum without panicking.
        let future_kind = PolicyKeyKind(0x0007);
        assert_ne!(future_kind, PolicyKeyKind::Ecc384);
    }
}
