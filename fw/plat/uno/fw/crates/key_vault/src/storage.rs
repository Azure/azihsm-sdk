// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backing storage abstraction for the key vault.
//!
//! The vault logic is generic over [`TableStorage`], which exposes one or
//! more fixed-size tables laid out exactly like the reference firmware's
//! `PhysicalTable` (and the `key_vault_table_t` RDL):
//!
//! ```text
//! table (17408 B):
//!   ENTRY[256]   8-byte metadata entries  (0x0000..0x0800)
//!   BITMAP[64]   block-allocator words    (0x0800..0x0900)
//!   BLOB         15104-byte key data      (0x0900..0x4400)
//! ```
//!
//! Firmware backs this with the GSRAM `KeyVaultTableTRegs` via a
//! `StaticRef`; host tests back it with owned, aligned memory. Keeping the
//! storage behind a trait is what lets the allocator, layout, and error
//! logic be exercised on the host without real GSRAM.

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmVaultKeyAttrs;
use zerocopy::FromBytes;
use zerocopy::Immutable;
use zerocopy::IntoBytes;
use zerocopy::KnownLayout;

use crate::entry::Entry;

/// Maximum number of tables (one per partition resource); matches the
/// reference firmware's `MAX_TABLE_COUNT` and the `KEY_VAULT[65]` region.
pub const MAX_TABLE_COUNT: usize = 65;

/// Metadata entry slots per table.
pub const ENTRIES_PER_TABLE: usize = 256;

/// Block-allocator bitmap words per table (`64 × u32 = 2048` block bits).
pub const BITMAP_WORDS: usize = 64;

/// Key-data blob region size per table, in bytes (`17408 - 2304`).
pub const BLOB_SIZE: usize = 15104;

/// Attribute blob prepended to every key in the blob region.
pub const ATTRIBUTES_BLOB_SIZE: usize = 32;

/// Blob allocation granularity, in bytes. Entry block offsets and key
/// storage sizes are multiples of this.
pub const BLOCK_ALIGNMENT: usize = 8;

/// Number of allocatable blocks in a table's blob region.
pub const BLOB_BLOCKS: usize = BLOB_SIZE / BLOCK_ALIGNMENT;

/// Key attribute blob (32 bytes, prepended to every stored key).
///
/// Layout:
/// - [0..8)   `HsmVaultKeyAttrs` (u64, little-endian)
/// - [8..24)  reserved (must be zero)
/// - [24..26) variable-length key length field (u16, zero for fixed-size kinds)
/// - [26..32) reserved (must be zero)
#[repr(C)]
#[derive(IntoBytes, Immutable, KnownLayout, FromBytes, Clone, Copy, Debug)]
pub struct Attributes {
    /// Key attributes (capability flags).
    pub attrs: HsmVaultKeyAttrs,
    /// Reserved, must be zero.
    _reserved_8_24: [u8; 16],
    /// Persisted length for variable-length keys; zero for fixed-size kinds.
    pub var_len: u16,
    /// Reserved, must be zero.
    _reserved_26_32: [u8; 6],
}

impl Attributes {
    /// All-zeros attributes (no attrs set, zero length).
    pub const ZERO: Self = Attributes {
        attrs: HsmVaultKeyAttrs::from_bits(0),
        _reserved_8_24: [0; 16],
        var_len: 0,
        _reserved_26_32: [0; 6],
    };
}

/// One vault table's storage.
///
/// Provides abstraction over per-partition metadata entries, block allocation bitmaps,
/// and key blob regions. Indices are caller-validated; the storage trait carries no
/// key-format knowledge. Metadata entries are stored and retrieved as raw little-endian
/// bytes; [`zerocopy`] handles bitfield packing via [`crate::entry::Entry`].
pub trait TableStorage {
    /// Total number of addressable table slots.
    ///
    /// This is the maximum table index space (always [`MAX_TABLE_COUNT`] = 65),
    /// not the count of tables actually owned by the partition. Use
    /// [`is_valid_table`](Self::is_valid_table) to test whether a specific table
    /// is owned.
    ///
    /// # Returns
    ///
    /// The total number of addressable table slots (65).
    fn table_count(&self) -> usize;

    /// Returns whether the partition owns the specified table.
    ///
    /// Tables are gated by the partition's resource mask. A table is valid if its
    /// index is within `0..table_count()` AND its bit is set in the partition's
    /// resource mask. If the mask is all-zero, no tables are valid.
    ///
    /// # Parameters
    ///
    /// - `table`: The 0-indexed table number to check (0..65).
    ///
    /// # Returns
    ///
    /// `true` if the partition owns this table; `false` if out of range or masked out.
    fn is_valid_table(&self, table: usize) -> bool;

    /// Borrows a metadata entry from the table.
    ///
    /// `Entry` is a transparent `u64` over the table's backing bytes, so
    /// this is an infallible view (no decoding step).
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid per [`is_valid_table`](Self::is_valid_table)).
    /// - `idx`: The entry slot index within the table (0..256).
    ///
    /// # Returns
    ///
    /// A shared reference to the `Entry` at `(table, idx)`.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` or `idx` is out of range.
    fn entry(&self, table: usize, idx: usize) -> HsmResult<&Entry>;

    /// Mutably borrows a metadata entry in the table.
    ///
    /// Callers mutate entry fields in place through this borrow; the
    /// change is written straight to the table's backing store.
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid).
    /// - `idx`: The entry slot index within the table (0..256).
    ///
    /// # Returns
    ///
    /// An exclusive reference to the `Entry` at `(table, idx)`.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` or `idx` is out of range.
    fn entry_mut(&mut self, table: usize, idx: usize) -> HsmResult<&mut Entry>;

    /// Borrows the block-allocator bitmap for a table (immutably).
    ///
    /// The bitmap tracks which [`BLOB_BLOCKS`] are in use (1 = used, 0 = free).
    /// Contains 64 × 32-bit words = 2048 bits = 2048 blocks.
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid).
    ///
    /// # Returns
    ///
    /// Reference to the 64-word bitmap array. The allocator reads through this borrow.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` is out of range.
    fn bitmap(&self, table: usize) -> HsmResult<&[u32; BITMAP_WORDS]>;

    /// Borrows the block-allocator bitmap for a table (mutably).
    ///
    /// The allocator mutates the bitmap directly through this borrow to track
    /// block allocations, avoiding a working copy. Blocks are marked (1 = used)
    /// and unmarked (0 = free) in place.
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid).
    ///
    /// # Returns
    ///
    /// Mutable reference to the 64-word bitmap array for allocation and deallocation.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` is out of range.
    fn bitmap_mut(&mut self, table: usize) -> HsmResult<&mut [u32; BITMAP_WORDS]>;

    /// Borrows the key blob region of a table (immutably).
    ///
    /// The blob holds all key materials and attribute data for the partition's keys
    /// in this table. Each key occupies a block-aligned run starting at an offset
    /// determined by the entry's `block_offset` field (in blocks, not bytes).
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid).
    ///
    /// # Returns
    ///
    /// Reference to the 15104-byte blob region as a `DmaBuf` (DMA-aligned memory).
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` is out of range.
    fn blob(&self, table: usize) -> HsmResult<&DmaBuf>;

    /// Borrows the key blob region of a table (mutably).
    ///
    /// Allows reading and writing key material and attributes. Used for key creation
    /// (writing), deletion (zeroizing), and lookups (reading). Large operations go
    /// through the [`HsmGdmaController`](azihsm_fw_hsm_pal_traits::HsmGdmaController)
    /// trait; small ones may use CPU direct access.
    ///
    /// # Parameters
    ///
    /// - `table`: The table index (0-indexed, must be valid).
    ///
    /// # Returns
    ///
    /// Mutable reference to the 15104-byte blob region for key operations.
    ///
    /// # Errors
    ///
    /// [`HsmError::InvalidArg`](azihsm_fw_hsm_pal_traits::HsmError::InvalidArg)
    /// if `table` is out of range.
    fn blob_mut(&mut self, table: usize) -> HsmResult<&mut DmaBuf>;
}
