// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format constants and the fixed-layout [`MaskedKeyMetadata`]
//! struct that occupies the AEAD envelope's AAD region.
//!
//! The masked-key blob is a thin schema over
//! [`azihsm_fw_core_crypto_aead_envelope`]: the envelope's AAD is
//! exactly one fixed 96-byte [`MaskedKeyMetadata`] record, and the
//! envelope's ciphertext is the masked plaintext key.
//!
//! ```text
//!   off    0           8          20                         116
//!         ┌───────────┬──────────┬────────────────────────┬─────────┬─────┐
//!         │ AEAD hdr  │   IV     │  MaskedKeyMetadata     │   CT    │ TAG │
//!         │   8 B     │  12 B    │        96 B            │  N B    │16 B │
//!         └───────────┴──────────┴────────────────────────┴─────────┴─────┘
//! ```
//!
//! Every byte from offset 0 through `116 + N` (exclusive of the
//! trailing tag itself) is authenticated by the GCM tag, including
//! the magic, version, `key_kind`, `usage_flags`, `svn`,
//! `owner_seed_id`, `key_label`, and the entire reserved tail of
//! [`MaskedKeyMetadata`]. Any single-bit flip is caught at
//! [`unmask`](crate::aead::unmask) before the `target_key` is exposed.

use azihsm_fw_core_crypto_aead_envelope::AeadAlg;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use zerocopy::little_endian::U16 as Le16;
use zerocopy::little_endian::U64 as Le64;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;
use zerocopy::Unaligned;

// =============================================================================
// Sizing constants
// =============================================================================

/// Fixed `MaskedKeyMetadata` size in bytes (== AAD length).
pub(crate) const META_LEN: usize = 96;

/// Length of the reserved tail in [`MaskedKeyMetadata`].
const RESERVED_LEN: usize = 38;

/// Maximum length in bytes of a caller-supplied `key_label`. Labels
/// are left-justified in a fixed 32-byte slot and zero-padded; the
/// decoder rejects blobs whose `key_label_len` exceeds this limit or
/// whose pad bytes are non-zero.
pub const KEY_LABEL_MAX: usize = 32;

/// Total masked-key blob length for an AEAD algorithm and a
/// `target_key_len`-byte target key. Crate-private — callers
/// discover the blob size via [`mask`](crate::aead::mask) with
/// `out = None`.
#[inline]
pub(crate) const fn blob_len(alg: AeadAlg, target_key_len: usize) -> usize {
    alg.envelope_len(target_key_len, META_LEN)
}

// =============================================================================
// Magic / version constants
// =============================================================================

/// Metadata magic — 4 ASCII bytes `b"MKEY"` at offset 0 of every
/// [`MaskedKeyMetadata`]. Identifies the 96 B AAD region as
/// masked-key metadata (vs. some other aead_envelope user's AAD
/// schema).
pub const META_MAGIC: [u8; 4] = *b"MKEY";

/// Metadata schema version. Bumped only when the byte layout of
/// [`MaskedKeyMetadata`] changes meaning; purely additive use of
/// reserved bytes (e.g. defining a new `HsmVaultKeyAttrs` bit) does
/// NOT bump this.
pub const META_VERSION_V1: u16 = 1;

// =============================================================================
// MaskedKeyMetadata
// =============================================================================

/// Fixed 96-byte metadata record that occupies the AEAD envelope's
/// AAD region.
///
/// `repr(C)` with little-endian wire fields; readable / writable via
/// [`zerocopy`] without copies. Field layout:
///
/// ```text
///  Off  Len  Field            Notes
///  ─────────────────────────────────────────────────────────────────────
///    0    4  magic            b"MKEY"
///    4    2  version    LE    = 1
///    6    1  key_kind         HsmVaultKeyKind raw (open_enum, repr(u8))
///    7    1  key_label_len    actual key_label length, ≤ KEY_LABEL_MAX
///    8    8  usage_flags LE   HsmVaultKeyAttrs::into_bits()
///   16    8  svn         LE   partition SVN at mask time
///   24    2  owner_seed_id LE  owner-seed (BKS2) lineage identifier
///   26   32  key_label        left-justified, zero-padded
///   58   38  _reserved        = 0 (future-extension space)
/// ```
///
/// The `key_kind` and `usage_flags` bits are passed through unchanged
/// from / to the vault types. Decoders use
/// [`HsmVaultKeyKind`](azihsm_fw_hsm_pal_traits::HsmVaultKeyKind)'s
/// `open_enum` to surface unknown discriminants as `Unknown(u8)`
/// without failing — forward-compat with future firmware that
/// defines additional kinds.
///
/// `svn` and `owner_seed_id` bind the blob to the platform identity
/// that produced it: a blob masked under one `{svn, owner_seed_id}`
/// pair cannot be replayed against a different one (the decoder
/// surfaces the values but does not enforce a policy — callers
/// compare them against their current PAL values).
#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct MaskedKeyMetadata {
    /// Magic — MUST equal [`META_MAGIC`] (`b"MKEY"`).
    pub magic: [u8; 4],
    /// Schema version — MUST equal [`META_VERSION_V1`] (currently `1`).
    pub version: Le16,
    /// Raw [`HsmVaultKeyKind`] byte.
    pub key_kind: u8,
    /// Actual `key_label` length in bytes. MUST be `≤ KEY_LABEL_MAX`.
    pub key_label_len: u8,
    /// Raw [`HsmVaultKeyAttrs`] bits (little-endian `u64`).
    pub usage_flags: Le64,
    /// Partition SVN at mask time.
    pub svn: Le64,
    /// Owner-seed (BKS2) lineage identifier (from
    /// `part_bks2_id`).
    pub owner_seed_id: Le16,
    /// Caller-supplied label, left-justified and zero-padded to
    /// [`KEY_LABEL_MAX`] bytes.
    pub key_label: [u8; KEY_LABEL_MAX],
    /// Reserved future-extension space. MUST be all-zero on v1.
    pub _reserved: [u8; RESERVED_LEN],
}

const _: () = assert!(core::mem::size_of::<MaskedKeyMetadata>() == META_LEN);

impl MaskedKeyMetadata {
    /// Build a v1 metadata record from caller-supplied vault fields,
    /// platform-identity bindings, and an opaque label.
    ///
    /// Magic, version, padding, and the reserved tail are filled in
    /// by this constructor and cannot be overridden — guaranteeing
    /// that every record this crate produces satisfies
    /// [`validate_v1`](Self::validate_v1).
    ///
    /// # Errors
    ///
    /// * [`HsmError::InvalidArg`] — `key_label.len() > KEY_LABEL_MAX`.
    pub fn new_v1(
        key_kind: HsmVaultKeyKind,
        usage_flags: HsmVaultKeyAttrs,
        svn: u64,
        owner_seed_id: u16,
        key_label: &[u8],
    ) -> HsmResult<Self> {
        if key_label.len() > KEY_LABEL_MAX {
            return Err(HsmError::InvalidArg);
        }
        let mut label_slot = [0u8; KEY_LABEL_MAX];
        label_slot[..key_label.len()].copy_from_slice(key_label);
        Ok(Self {
            magic: META_MAGIC,
            version: Le16::new(META_VERSION_V1),
            key_kind: key_kind.0,
            key_label_len: key_label.len() as u8,
            usage_flags: Le64::new(usage_flags.into_bits()),
            svn: Le64::new(svn),
            owner_seed_id: Le16::new(owner_seed_id),
            key_label: label_slot,
            _reserved: [0; RESERVED_LEN],
        })
    }

    /// Decoded [`HsmVaultKeyKind`]. Returns the open-enum wrapper so
    /// callers can distinguish known variants from `Unknown(byte)`.
    #[inline]
    pub fn key_kind(&self) -> HsmVaultKeyKind {
        HsmVaultKeyKind(self.key_kind)
    }

    /// Decoded [`HsmVaultKeyAttrs`] bitfield.
    #[inline]
    pub fn usage_flags(&self) -> HsmVaultKeyAttrs {
        HsmVaultKeyAttrs::from_bits(self.usage_flags.get())
    }

    /// Borrowed view of the caller-supplied label (first
    /// `key_label_len` bytes of the slot).
    ///
    /// Returns [`HsmError::MaskedKeyDecodeFailed`] if `key_label_len`
    /// exceeds [`KEY_LABEL_MAX`] (should never happen on a record
    /// that passed [`validate_v1`](Self::validate_v1)).
    #[inline]
    pub fn key_label(&self) -> HsmResult<&[u8]> {
        let n = self.key_label_len as usize;
        if n > KEY_LABEL_MAX {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        Ok(&self.key_label[..n])
    }

    /// Validate every field of the parsed metadata against v1's
    /// invariants. Returns [`HsmError::MaskedKeyDecodeFailed`] for
    /// any violation:
    ///
    /// * magic mismatch
    /// * `version != META_VERSION_V1`
    /// * `key_label_len > KEY_LABEL_MAX`
    /// * non-zero pad bytes after `key_label[..key_label_len]`
    /// * non-zero reserved tail
    ///
    /// `key_kind`, `usage_flags`, `svn`, and `owner_seed_id` are NOT
    /// validated here — the open-enum kind surfaces unknown values as
    /// `Unknown(u8)`, the attribute bitfield reserves its high bits
    /// for future use, and the platform-identity bindings are policy
    /// fields for the caller to compare against current PAL values.
    pub(crate) fn validate_v1(&self) -> HsmResult<()> {
        if self.magic != META_MAGIC
            || self.version.get() != META_VERSION_V1
            || (self.key_label_len as usize) > KEY_LABEL_MAX
            || !self._reserved.iter().all(|&b| b == 0)
        {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        // Pad bytes after the label MUST be zero — prevents callers
        // from smuggling unbound-looking data through the slack.
        let n = self.key_label_len as usize;
        if !self.key_label[n..].iter().all(|&b| b == 0) {
            return Err(HsmError::MaskedKeyDecodeFailed);
        }
        Ok(())
    }
}
