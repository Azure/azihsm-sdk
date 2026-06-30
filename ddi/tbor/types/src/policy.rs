// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side mirror of the partition policy ([`PartPolicy`]) byte
//! layout.
//!
//! Faithful mirror of `azihsm_fw_ddi_tbor_types::policy` — defined
//! locally so this (host) crate has no firmware dependency. The byte
//! layout MUST stay in sync with the firmware definition; the
//! `const _: () = assert!(...)` blocks at the bottom pin the absolute
//! sizes so any drift fails the build.
//!
//! Layout discipline:
//!
//! * Every multi-byte scalar is stored as a little-endian byte array
//!   native `#[repr(C)]` `u16` (alignment-2); a trailing `_reserved`
//!   byte pads [`PartPolicy`] to an even, padding-free size. All
//!   supported targets are little-endian, so the in-memory image equals
//!   the wire image. The firmware copies the policy out of the wire
//!   buffer (`try_read_from_bytes`), so no buffer-alignment plumbing is
//!   needed.
//! * `#[repr(C)]` + zerocopy [`TryFromBytes`] / [`IntoBytes`] /
//!   [`Immutable`] / [`KnownLayout`] derives reject any padding /
//!   alignment drift at compile time.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;

/// Maximum key length for [`PolicyPubKey::data`] (bytes).
///
/// Raw P-384 public-key coordinates `X ‖ Y` (48 + 48); the SEC1
/// uncompressed-point `0x04` prefix is **not** stored.
pub const POLICY_MAX_KEY_LEN: usize = 96;

/// Caller-provided opaque info bytes embedded in [`PartPolicy::info`].
pub const POLICY_INFO_LEN: usize = 64;

/// Length of the backup partition identifier ([`PartPolicy::backup_part_id`]).
pub const POLICY_BACKUP_PART_ID_LEN: usize = 16;

/// Supported [`PolicyVer::major`] value.  Parsers must reject any
/// other major version.
pub const POLICY_VERSION_MAJOR: u8 = 1;

/// Discriminants for [`PolicyPubKey::kind`].
///
/// Stored in the wire layout as little-endian `[u8; 2]`.  The
/// open-enum form keeps the type forward-compatible: a future spec
/// value gets a new associated `pub const` without breaking exhaustive
/// matches in older code.
#[repr(u16)]
#[open_enum]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
pub enum PolicyKeyKind {
    /// ECC P-384 public key.
    Ecc384 = 0,
}

/// Two-byte policy version (`major.minor`).
///
/// Layout (alignment 1, size 2 B): `major(1) ‖ minor(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PolicyVer {
    /// Major version number.  Must equal [`POLICY_VERSION_MAJOR`].
    pub major: u8,

    /// Minor version number.  Any value accepted (forward-compat).
    pub minor: u8,
}

/// POTA public key embedded in [`PartPolicy`].
///
/// Layout (alignment 2, size 100 B): `kind(2 LE) ‖ len(2 LE) ‖ data(96)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PolicyPubKey {
    /// [`PolicyKeyKind`] discriminant. Native, little-endian on all
    /// supported targets (open-enum newtype over `u16`).
    pub kind: PolicyKeyKind,

    /// Active prefix length of `data` (`0..=POLICY_MAX_KEY_LEN`).
    /// For `Ecc384` must equal [`POLICY_MAX_KEY_LEN`].
    pub len: u16,

    /// Key bytes; only the first `len` bytes are meaningful.
    pub data: [u8; POLICY_MAX_KEY_LEN],
}

/// Boolean policy flags, packed into a single byte (alignment 1).
///
/// Layout (size 1 B): bit 0 = `include_fmc_cdi`, bit 1 =
/// `require_trusted_sa_key`, bit 2 = `allow_peer_cloning`; bits 3..8
/// are reserved and must be zero.  Backed by a `#[bitfield(u8)]` so the
/// struct stays alignment-1 / padding-free (`#[repr(transparent)]` over
/// `u8`); the generated `include_fmc_cdi()` / `with_*()` accessors
/// decode and build the bits.
///
/// The bitfield macro ignores the reserved (`__`) bits, so the wire
/// contract "reserved bits MUST be zero" is enforced separately by
/// [`PolicyFlags::is_valid`].
#[bitfield(u8)]
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct PolicyFlags {
    /// Bit 0: include the First Mutable Composite Device Identity
    /// (CDI-FMC) in key derivations.
    pub include_fmc_cdi: bool,

    /// Bit 1: require the remote sealing key to be anchored in a
    /// trusted Sealing Authority key.
    pub require_trusted_sa_key: bool,

    /// Bit 2: allow cloning of the security domain to a peer partition
    /// endorsed by the same POTA.
    pub allow_peer_cloning: bool,

    /// Bits 3..8: reserved, must be zero on the wire (see
    /// [`PolicyFlags::is_valid`]).
    #[bits(5)]
    __: u8,
}

impl PolicyFlags {
    /// Bit 0: include the First Mutable Composite Device Identity
    /// (CDI-FMC) in key derivations.
    pub const INCLUDE_FMC_CDI: u8 = 1 << 0;

    /// Bit 1: require the remote sealing key to be anchored in a
    /// trusted Sealing Authority key.
    pub const REQUIRE_TRUSTED_SA_KEY: u8 = 1 << 1;

    /// Bit 2: allow cloning of the security domain to a peer partition
    /// endorsed by the same POTA.
    pub const ALLOW_PEER_CLONING: u8 = 1 << 2;

    /// Mask of all currently-defined flag bits; any bit outside this
    /// mask is reserved and must be zero on the wire.
    pub const KNOWN_MASK: u8 =
        Self::INCLUDE_FMC_CDI | Self::REQUIRE_TRUSTED_SA_KEY | Self::ALLOW_PEER_CLONING;

    /// `true` iff only known flag bits are set (no reserved bits).
    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.into_bits() & !Self::KNOWN_MASK == 0
    }
}

/// Unified partition policy as it appears on the `PartInit` /
/// `PartFinal` wire.
///
/// Carries both the partition-level fields (POTA trust anchor, CDI-FMC
/// flag) and the security-domain fields (Sealing Authority + its POTA
/// trust anchors, backing-partition identity, the trusted-SA /
/// peer-cloning flags).  Pubkey slots that are not in use carry
/// `len = 0` (see [`PolicyPubKey`]).
///
/// Layout (alignment 2, size 484 B):
///
/// | Field                 | Offset | Size |
/// |-----------------------|--------|------|
/// | `version`             | 0      | 2    |
/// | `pota_pub_key`        | 2      | 100  |
/// | `sata_pub_key`        | 102    | 100  |
/// | `sapota_pub_key`      | 202    | 100  |
/// | `backup_part_id`      | 302    | 16   |
/// | `backup_part_pub_key` | 318    | 100  |
/// | `flags`               | 418    | 1    |
/// | `info`                | 419    | 64   |
/// | `_reserved`           | 483    | 1    |
#[derive(Debug, Clone, PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct PartPolicy {
    /// Policy version (major.minor).
    pub version: PolicyVer,

    /// POTA (Partition Owner Trust Anchor) public key bound to this
    /// partition.
    pub pota_pub_key: PolicyPubKey,

    /// SATA (Sealing Authority Trust Anchor) public key for the
    /// security domain.
    pub sata_pub_key: PolicyPubKey,

    /// SAPOTA (Sealing Authority's POTA) public key.  Optional —
    /// carries `len = 0` when not provisioned.
    pub sapota_pub_key: PolicyPubKey,

    /// Identifier of the backing partition that created the security
    /// domain backup.  All-zero when not applicable.
    pub backup_part_id: [u8; POLICY_BACKUP_PART_ID_LEN],

    /// Public key of the backing partition.  Optional — carries
    /// `len = 0` when not provisioned.
    pub backup_part_pub_key: PolicyPubKey,

    /// Boolean policy flags (CDI-FMC, trusted-SA, peer-cloning).
    pub flags: PolicyFlags,

    /// Caller-provided opaque info bound into the partition's attested
    /// state.
    pub info: [u8; POLICY_INFO_LEN],

    /// Reserved padding byte (MUST be zero) that rounds the struct to an
    /// even, alignment-2-clean size with no implicit padding.
    pub _reserved: u8,
}

impl PartPolicy {
    /// An all-zero policy. Useful as a base for builders and as the
    /// default for owned request structs (the contained byte arrays are
    /// larger than 32 B, so `#[derive(Default)]` is unavailable).
    pub const fn zeroed() -> Self {
        const ZERO_KEY: PolicyPubKey = PolicyPubKey {
            kind: PolicyKeyKind(0),
            len: 0,
            data: [0; POLICY_MAX_KEY_LEN],
        };
        Self {
            version: PolicyVer { major: 0, minor: 0 },
            pota_pub_key: ZERO_KEY,
            sata_pub_key: ZERO_KEY,
            sapota_pub_key: ZERO_KEY,
            backup_part_id: [0; POLICY_BACKUP_PART_ID_LEN],
            backup_part_pub_key: ZERO_KEY,
            flags: PolicyFlags::new(),
            info: [0; POLICY_INFO_LEN],
            _reserved: 0,
        }
    }
}

impl Default for PartPolicy {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Byte size of [`PartPolicy`] in its on-wire layout.
pub const PART_POLICY_LEN: usize = core::mem::size_of::<PartPolicy>();

const _: () = assert!(PART_POLICY_LEN == 484);
const _: () = assert!(core::mem::align_of::<PartPolicy>() == 2);
const _: () = assert!(core::mem::size_of::<PolicyPubKey>() == 100);
const _: () = assert!(core::mem::align_of::<PolicyPubKey>() == 2);
const _: () = assert!(core::mem::size_of::<PolicyVer>() == 2);
const _: () = assert!(core::mem::size_of::<PolicyFlags>() == 1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_pinned() {
        assert_eq!(PART_POLICY_LEN, 484);
        assert_eq!(core::mem::align_of::<PartPolicy>(), 2);
    }

    #[test]
    fn zeroed_round_trips_through_bytes() {
        let policy = PartPolicy::zeroed();
        assert_eq!(IntoBytes::as_bytes(&policy), &[0u8; PART_POLICY_LEN][..]);
    }

    #[test]
    fn flag_accessors_decode_bits() {
        let flags =
            PolicyFlags::from_bits(PolicyFlags::INCLUDE_FMC_CDI | PolicyFlags::ALLOW_PEER_CLONING);
        assert!(flags.include_fmc_cdi());
        assert!(!flags.require_trusted_sa_key());
        assert!(flags.allow_peer_cloning());
        assert!(flags.is_valid());
    }
}
