// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Vault metadata entry — the 8-byte `PhysicalEntry`.
//!
//! Uses `bitfield-struct` for maintainable, zero-overhead bitfield packing
//! matching the RDL layout exactly:
//!
//! ```text
//! DW0: OFFSET[15:0] DISABLED[16] SESSION[17] rsvd[31:18]
//! DW1: SESSION_OR_TAG[15:0] KIND[23:16] APP_ID[31:24]
//! ```
//!
//! `OFFSET` is a *block* index (× [`BLOCK_ALIGNMENT`] = byte offset into
//! the blob region), matching the reference firmware.

#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::HsmVaultKeyKind;
use bitfield_struct::bitfield;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::storage::BLOCK_ALIGNMENT;

/// Decoded 8-byte metadata entry.
///
/// A packed bitfield struct representing the entry's layout in storage.
/// `Entry` is a transparent `u64` (8-byte aligned), so storage can hand
/// out `&Entry`/`&mut Entry` views directly over its backing bytes.
#[bitfield(u64)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes)]
pub struct Entry {
    /// Blob block index of this key's storage (× [`BLOCK_ALIGNMENT`] =
    /// byte offset of its attribute blob).
    #[bits(16)]
    pub block_offset: u16,
    /// Entry is present but disabled (not returned unless allowed).
    #[bits(1)]
    pub disabled: bool,
    /// Key is session-scoped (`session_or_tag` is a session id).
    #[bits(1)]
    pub session: bool,
    /// Reserved bits (must be zero).
    #[bits(14)]
    _reserved: u16,
    /// Session id (session-scoped keys) or key tag (app keys).
    #[bits(16)]
    pub session_or_tag: u16,
    /// Algorithm/size discriminant (stored as u8, convert to/from HsmVaultKeyKind).
    #[bits(8)]
    kind_byte: u8,
    /// Owning app/partition id.
    #[bits(8)]
    pub app_id: u8,
}

impl Entry {
    /// Returns whether this metadata entry slot is free (unused).
    ///
    /// An entry is considered free if its `kind` equals `HsmVaultKeyKind::Free`.
    /// Free entries are available for new key allocation.
    ///
    /// # Returns
    ///
    /// `true` if the entry represents an unused slot; `false` if it holds a live key.
    #[inline]
    pub fn is_free(&self) -> bool {
        self.kind() == HsmVaultKeyKind::Free
    }

    /// Computes the byte offset of this key's attribute blob within the vault's blob region.
    ///
    /// Converts the block-based offset stored in `block_offset` to a byte address
    /// by multiplying by [`BLOCK_ALIGNMENT`]. The resulting offset is relative to the
    /// start of the table's blob region (not absolute memory address).
    ///
    /// # Returns
    ///
    /// Byte offset from the start of the blob region to this key's attribute blob.
    /// Can be added to the blob base address to locate the actual attributes in memory.
    ///
    /// # Example
    ///
    /// With `block_offset = 5` and `BLOCK_ALIGNMENT = 8`:
    /// Returns `40` (5 × 8), the byte offset into the blob region.
    #[inline]
    pub fn attrs_byte_offset(&self) -> usize {
        usize::from(self.block_offset()) * BLOCK_ALIGNMENT
    }

    /// Gets the key kind.
    #[inline]
    pub fn kind(&self) -> HsmVaultKeyKind {
        // SAFETY: `HsmVaultKeyKind` is `#[open_enum] #[repr(u8)]`, so every
        // `u8` is a valid representation — the transmute is sound for any
        // stored kind byte.
        unsafe { core::mem::transmute::<u8, HsmVaultKeyKind>(self.kind_byte()) }
    }

    /// Sets the key kind.
    #[inline]
    pub fn set_kind(&mut self, kind: HsmVaultKeyKind) {
        // SAFETY: `HsmVaultKeyKind` is `#[open_enum] #[repr(u8)]`, a
        // transparent `u8`, so transmuting it back to its byte is sound.
        self.set_kind_byte(unsafe { core::mem::transmute::<HsmVaultKeyKind, u8>(kind) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mut e = Entry(0);
        e.set_block_offset(0x1234);
        e.set_disabled(true);
        e.set_session(true);
        e.set_session_or_tag(0xABCD);
        e.set_kind(HsmVaultKeyKind::Aes256);
        e.set_app_id(0x42);

        let bytes = e.as_bytes();
        let decoded = Entry::read_from_bytes(bytes).expect("8-byte entry is valid");

        assert_eq!(decoded.block_offset(), 0x1234);
        assert_eq!(decoded.disabled(), true);
        assert_eq!(decoded.session(), true);
        assert_eq!(decoded.session_or_tag(), 0xABCD);
        assert_eq!(decoded.kind(), HsmVaultKeyKind::Aes256);
        assert_eq!(decoded.app_id(), 0x42);
    }

    #[test]
    fn free_is_zero() {
        assert!(Entry::default().is_free());
        assert_eq!(Entry::default().as_bytes(), &[0u8; 8]);
    }

    #[test]
    fn bit_layout_matches_rdl() {
        // OFFSET[15:0], DISABLED[16], SESSION[17] in DW0;
        // SESSION_OR_TAG[15:0], KIND[23:16], APP_ID[31:24] in DW1.
        let mut e = Entry(0);
        e.set_block_offset(0xBEEF);
        e.set_disabled(true);
        e.set_session(false);
        e.set_session_or_tag(0x1357);
        e.set_kind(HsmVaultKeyKind(18)); // Aes256
        e.set_app_id(0x9A);

        let bytes = e.as_bytes();
        // Interpret as little-endian DWORDs for RDL verification
        let dw0 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let dw1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);

        assert_eq!(dw0 & 0xFFFF, 0xBEEF);
        assert_eq!((dw0 >> 16) & 1, 1); // disabled
        assert_eq!((dw0 >> 17) & 1, 0); // session
        assert_eq!(dw1 & 0xFFFF, 0x1357);
        assert_eq!((dw1 >> 16) & 0xFF, 18);
        assert_eq!((dw1 >> 24) & 0xFF, 0x9A);
    }

    #[test]
    fn attrs_byte_offset_scales_by_block() {
        let mut e = Entry::default();
        e.set_block_offset(5);
        assert_eq!(e.attrs_byte_offset(), 40); // 5 × 8
    }
}
