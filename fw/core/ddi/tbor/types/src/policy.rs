// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition policy ([`PartPolicy`]) byte layout.
//!
//! Canonical, single source of truth.  This crate is the DDI types
//! crate and must not depend on the firmware crate
//! (`azihsm_fw_hsm_core`) or on firmware-only primitives like
//! `DmaBuf` / `HsmError`.  The validation/parser surface
//! (`from_bytes(&DmaBuf) -> HsmResult<PartPolicy>`) that consumes
//! those firmware primitives lives in
//! `fw/core/lib/src/ddi/tbor/policy.rs` as a thin free function over
//! the types here.
//!
//! Layout discipline:
//!
//! * Multi-byte scalars use alignment-1 little-endian [`U16`]
//!   fields, so every type here — and [`PartPolicy`] as a whole — is
//!   alignment-1 / [`Unaligned`].  A trailing `_reserved` byte pads
//!   [`PartPolicy`] to an even size so there is no implicit padding
//!   (zerocopy `IntoBytes` rejects padding).
//! * Because the struct is [`Unaligned`], the firmware parser borrows it
//!   zero-copy from the (arbitrarily-aligned) wire buffer with
//!   `try_ref_from_bytes` — no copy, no buffer-alignment plumbing.
//! * `#[repr(C)]` + zerocopy [`TryFromBytes`] / [`IntoBytes`] /
//!   [`Immutable`] / [`KnownLayout`] / [`Unaligned`] derives reject any
//!   padding / alignment drift at compile time.
//! * The `const _: () = assert!(...)` blocks at the bottom pin
//!   absolute byte sizes as a belt-and-braces check.

use bitfield_struct::bitfield;
use open_enum::open_enum;
use zerocopy::little_endian::U16;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::TryFromBytes;
use zerocopy::Unaligned;

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
/// value gets a new associated `pub const` without breaking
/// exhaustive matches in older code (which already handle the
/// unknown-discriminant branch via the `_` arm).
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
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct PolicyVer {
    /// Major version number.  Must equal [`POLICY_VERSION_MAJOR`].
    pub major: u8,

    /// Minor version number.  Any value accepted (forward-compat).
    pub minor: u8,
}

/// POTA public key embedded in [`PartPolicy`].
///
/// Layout (alignment 1, size 100 B): `kind(2 LE) ‖ len(2 LE) ‖ data(96)`.
///
/// `kind` and `len` are stored as alignment-1 little-endian [`U16`] so
/// the whole struct (and [`PartPolicy`]) is [`Unaligned`] and can be
/// borrowed zero-copy from an arbitrarily-aligned wire buffer; read them
/// through [`kind`](Self::kind) / [`len`](Self::len).
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
pub struct PolicyPubKey {
    /// [`PolicyKeyKind`] discriminant, little-endian.  Read via
    /// [`kind`](Self::kind).
    kind: U16,

    /// Active prefix length of `data` (`0..=POLICY_MAX_KEY_LEN`),
    /// little-endian.  Read via [`len`](Self::len).  For `Ecc384` must
    /// equal [`POLICY_MAX_KEY_LEN`].
    len: U16,

    /// Key bytes; only the first `len()` bytes are meaningful.
    pub data: [u8; POLICY_MAX_KEY_LEN],
}

impl PolicyPubKey {
    /// The [`PolicyKeyKind`] discriminant.
    #[inline]
    pub fn kind(&self) -> PolicyKeyKind {
        PolicyKeyKind(self.kind.get())
    }

    /// Active prefix length of [`data`](Self::data).
    #[inline]
    pub fn len(&self) -> usize {
        self.len.get() as usize
    }

    /// `true` iff the key slot is absent (`len == 0`).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len.get() == 0
    }
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
#[derive(PartialEq, Eq, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct PolicyFlags {
    /// Bit 0: include the First Mutable Composite Device Identity
    /// (CDI-FMC) in key derivations.
    pub include_fmc_cdi: bool,

    /// Bit 1: require the remote sealing key to be anchored in a
    /// trusted (Manticore-based) Sealing Authority key.
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
    /// trusted (Manticore-based) Sealing Authority key.
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

/// Unified partition policy as it appears on the `PartInit` wire and in
/// PAL persistence.
///
/// This single struct carries both the partition-level fields (POTA
/// trust anchor, CDI-FMC flag) and the security-domain fields (Sealing
/// Authority + its POTA trust anchors, backing-partition identity, the
/// trusted-SA / peer-cloning flags) — there is no separate
/// security-domain policy type.  Pubkey slots that are not in use carry
/// `len = 0` (see [`PolicyPubKey`]).
///
/// Layout (alignment 1, size 484 B):
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
///
/// The trailing `_reserved` byte pads the struct to an even length so
/// the `#[repr(C)]` layout has no implicit padding (required for the
/// zerocopy `IntoBytes` derive).  Every field is alignment-1, so the
/// struct is [`Unaligned`] and can be borrowed zero-copy from an
/// arbitrarily-aligned wire buffer (`try_ref_from_bytes`) with no copy.
#[derive(Debug, TryFromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
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

/// Byte size of [`PartPolicy`] in its on-wire / on-disk layout.
///
/// Used by the [`crate::TborPartInitReq`] schema as the `len`
/// constant for its `part_policy` slice.  The `const _` assertions
/// below pin the value so any layout drift fails the build instead
/// of silently changing the wire size.
pub const PART_POLICY_LEN: usize = core::mem::size_of::<PartPolicy>();

const _: () = assert!(PART_POLICY_LEN == 484);
const _: () = assert!(core::mem::align_of::<PartPolicy>() == 1);
const _: () = assert!(core::mem::size_of::<PolicyPubKey>() == 100);
const _: () = assert!(core::mem::align_of::<PolicyPubKey>() == 1);
const _: () = assert!(core::mem::size_of::<PolicyVer>() == 2);
const _: () = assert!(core::mem::size_of::<PolicyFlags>() == 1);

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
        // Helper: write an Ecc384 (kind 0) raw X‖Y pubkey at `off`.
        fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
            // kind = Ecc384 = 0 (LE u16)
            bytes[off] = 0;
            bytes[off + 1] = 0;
            // len = 96 (LE u16)
            bytes[off + 2] = 96;
            bytes[off + 3] = 0;
            // data[0..96] = opaque non-zero coordinate bytes (raw X‖Y,
            // no SEC1 0x04 prefix)
            for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
                *b = (fill.wrapping_add(i as u8)) | 0x80;
            }
        }
        // pota_pub_key @ 2, sata_pub_key @ 102, sapota_pub_key @ 202
        write_pubkey(&mut bytes, 2, 0x10);
        write_pubkey(&mut bytes, 102, 0x20);
        write_pubkey(&mut bytes, 202, 0x30);
        // backup_part_id @ 302..318 = 0xCD
        for b in bytes[302..318].iter_mut() {
            *b = 0xCD;
        }
        // backup_part_pub_key @ 318
        write_pubkey(&mut bytes, 318, 0x40);
        // flags @ 418: include_fmc_cdi | allow_peer_cloning
        bytes[418] = PolicyFlags::INCLUDE_FMC_CDI | PolicyFlags::ALLOW_PEER_CLONING;
        // info @ 419..483 = 0xAB
        for b in bytes[419..483].iter_mut() {
            *b = 0xAB;
        }
        bytes
    }

    #[test]
    fn known_good_bytes_parses() {
        let bytes = known_good_bytes();
        let policy = PartPolicy::try_read_from_bytes(&bytes).expect("parse");
        assert_eq!(policy.version.major, 1);
        assert_eq!(policy.version.minor, 0);
        assert_eq!(policy.pota_pub_key.kind(), PolicyKeyKind::Ecc384);
        assert_eq!(policy.pota_pub_key.len(), 96);
        assert_eq!(policy.sata_pub_key.len(), 96);
        assert_eq!(policy.sapota_pub_key.len(), 96);
        assert!(policy.backup_part_id.iter().all(|&b| b == 0xCD));
        assert!(policy.flags.include_fmc_cdi());
        assert!(!policy.flags.require_trusted_sa_key());
        assert!(policy.flags.allow_peer_cloning());
        assert!(policy.flags.is_valid());
        assert!(policy.info.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn round_trip_known_good_bytes() {
        let bytes = known_good_bytes();
        let policy = PartPolicy::try_read_from_bytes(&bytes).expect("known-good bytes parse");
        let serialised = IntoBytes::as_bytes(&policy);
        assert_eq!(serialised, &bytes);
    }

    #[test]
    fn wrong_length_rejected_by_try_from_bytes() {
        let too_short = [0u8; PART_POLICY_LEN - 1];
        assert!(PartPolicy::try_read_from_bytes(&too_short).is_err());
        let too_long = [0u8; PART_POLICY_LEN + 1];
        assert!(PartPolicy::try_read_from_bytes(&too_long).is_err());
    }

    #[test]
    fn part_policy_len_pin() {
        assert_eq!(PART_POLICY_LEN, 484);
    }

    #[test]
    fn policy_flags_decode_and_validate() {
        let f = PolicyFlags::from_bits(PolicyFlags::REQUIRE_TRUSTED_SA_KEY);
        assert!(!f.include_fmc_cdi());
        assert!(f.require_trusted_sa_key());
        assert!(!f.allow_peer_cloning());
        assert!(f.is_valid());
        // A reserved bit set => invalid.
        let bad = PolicyFlags::from_bits(1 << 7);
        assert!(!bad.is_valid());
    }

    #[test]
    fn open_enum_unknown_kind_is_representable() {
        // Forward-compat smoke: a future spec value (e.g. 0x0007)
        // round-trips through the open enum without panicking.
        let future_kind = PolicyKeyKind(0x0007);
        assert_ne!(future_kind, PolicyKeyKind::Ecc384);
    }
}
