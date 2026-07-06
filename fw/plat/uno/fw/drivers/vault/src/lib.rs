// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM-backed [`TableStorage`] for the Uno key vault.
//!
//! This driver owns the SoC-specific knowledge of where the key-vault
//! tables live in GSRAM (the `key_vault_table_t` RDL layout) and how to
//! access them, so the PAL's [`HsmVault`](azihsm_fw_hsm_pal_traits::HsmVault)
//! implementation can stay free of `reg_soc` dependencies.
//!
//! GSRAM is plain shared SRAM (not a peripheral), so the accessors use
//! ordinary non-volatile reads/writes over the RDL-defined table layout —
//! letting the compiler coalesce metadata/bitmap accesses into block
//! transfers. The platform-agnostic allocator and key logic live in the
//! [`KeyVault`](azihsm_fw_uno_key_vault::KeyVault) crate; this driver only
//! provides the storage substrate.

#![no_std]
#![allow(unsafe_code)]

use azihsm_fw_hsm_pal_traits::DmaBuf;
use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_key_vault::Entry;
use azihsm_fw_uno_key_vault::TableStorage;
use azihsm_fw_uno_key_vault::BITMAP_WORDS;
use azihsm_fw_uno_key_vault::BLOB_SIZE;
use azihsm_fw_uno_key_vault::ENTRIES_PER_TABLE;
use azihsm_fw_uno_key_vault::MAX_TABLE_COUNT;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;
use azihsm_fw_uno_reg_soc::key_vault_table_t::BITMAP_OFFSET;
use azihsm_fw_uno_reg_soc::key_vault_table_t::BLOB_OFFSET;
use azihsm_fw_uno_reg_soc::key_vault_table_t::BLOB_SIZE as TABLE_BLOB_SIZE;
use azihsm_fw_uno_reg_soc::key_vault_table_t::ENTRY_OFFSET;
use azihsm_fw_uno_reg_soc::key_vault_table_t::ENTRY_STRIDE;
use azihsm_fw_uno_reg_soc::key_vault_table_t::KEY_VAULT_TABLE_T_BASE;

/// Size of the global key-vault table index space.
///
/// All 65 tables are addressable in GSRAM; which tables a partition may
/// actually use is gated per-operation by its resource mask (see
/// [`VaultStorage::is_valid_table`]).
const TABLE_COUNT: usize = MAX_TABLE_COUNT;

/// Absolute GSRAM address of the first vault table.
const TABLE_BASE: u32 = IO_GSRAM_BASE + KEY_VAULT_TABLE_T_BASE;

/// Bytes between consecutive vault tables (metadata + bitmap + blob).
///
/// The blob is the last region in a table, so the stride is its offset
/// plus its size. Derived from generated RDL constants — the key-vault
/// table is plain GSRAM, accessed without the tock-registers overlay.
const TABLE_STRIDE: u32 = BLOB_OFFSET + TABLE_BLOB_SIZE;

/// GSRAM-backed [`TableStorage`].
///
/// Tables are addressed directly in GSRAM, so the only state this handle
/// carries is the calling partition's resource mask: bit `i` selects
/// global key-vault table `i`. A fresh handle is built per vault
/// operation from the partition's `res_mask`.
#[derive(Debug)]
pub struct VaultStorage {
    /// 128-bit table-ownership mask for the calling partition.
    res_mask: u128,
}

impl VaultStorage {
    /// Builds a storage handle for a partition owning the tables selected
    /// by `res_mask` (bit `i` selects global key-vault table `i`).
    ///
    /// # Parameters
    ///
    /// - `res_mask`: 128-bit table-ownership mask; bit `i` set means the
    ///   partition owns global key-vault table `i`.
    ///
    /// # Returns
    ///
    /// A `VaultStorage` handle scoped to the partition's owned tables.
    #[inline]
    pub fn new(res_mask: u128) -> Self {
        Self { res_mask }
    }

    /// Absolute GSRAM address of table `table`'s entry-metadata region.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index (`0..TABLE_COUNT`).
    ///
    /// # Returns
    ///
    /// The absolute GSRAM byte address of the table's entry region.
    #[inline]
    fn entry_addr(table: usize) -> usize {
        (TABLE_BASE + table as u32 * TABLE_STRIDE + ENTRY_OFFSET) as usize
    }

    /// Absolute GSRAM address of table `table`'s block-allocator bitmap.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index (`0..TABLE_COUNT`).
    ///
    /// # Returns
    ///
    /// The absolute GSRAM byte address of the table's bitmap region.
    #[inline]
    fn bitmap_addr(table: usize) -> usize {
        (TABLE_BASE + table as u32 * TABLE_STRIDE + BITMAP_OFFSET) as usize
    }

    /// Absolute GSRAM address of table `table`'s key-data blob region.
    ///
    /// Exposed so a caller with `'static` GSRAM can build a key reference
    /// with its own lifetime (see [`KeyVault::key_location`]).
    ///
    /// [`KeyVault::key_location`]: azihsm_fw_uno_key_vault::KeyVault::key_location
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index (`0..TABLE_COUNT`).
    ///
    /// # Returns
    ///
    /// The absolute GSRAM byte address of the table's blob region.
    #[inline]
    pub fn blob_addr(table: usize) -> usize {
        (TABLE_BASE + table as u32 * TABLE_STRIDE + BLOB_OFFSET) as usize
    }
}

impl TableStorage for VaultStorage {
    /// Returns the global key-vault table index space size.
    ///
    /// # Returns
    ///
    /// The total number of addressable tables; not all are necessarily
    /// owned by the calling partition.
    fn table_count(&self) -> usize {
        TABLE_COUNT
    }

    /// Returns whether the calling partition may use `table`.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index to test.
    ///
    /// # Returns
    ///
    /// `true` if `table` is addressable and its bit is set in the
    /// partition's resource mask; `false` otherwise.
    fn is_valid_table(&self, table: usize) -> bool {
        // A table is usable only if it is addressable and owned by the
        // calling partition (its bit is set in the resource mask).
        table < TABLE_COUNT && (self.res_mask >> table) & 1 != 0
    }

    /// Borrows a metadata entry from GSRAM.
    ///
    /// `Entry` is a transparent `u64`; the GSRAM entry slot is 8-byte
    /// aligned, so the byte region is reinterpreted directly as an
    /// `&Entry` (no decoding step).
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    /// - `idx`: Entry slot index within the table (`0..ENTRIES_PER_TABLE`).
    ///
    /// # Returns
    ///
    /// A shared reference to the [`Entry`] at `(table, idx)` in GSRAM.
    fn entry(&self, table: usize, idx: usize) -> HsmResult<&Entry> {
        if table >= TABLE_COUNT || idx >= ENTRIES_PER_TABLE {
            return Err(HsmError::InvalidArg);
        }
        let ptr = (Self::entry_addr(table) + idx * ENTRY_STRIDE as usize) as *const Entry;
        // SAFETY: the bounds check above keeps the access within table
        // `table`'s entry region (8-byte aligned). GSRAM key-vault tables are
        // plain shared SRAM (no read side effects); `Entry` is a transparent
        // `u64`, so every bit pattern is a valid value.
        Ok(unsafe { &*ptr })
    }

    /// Mutably borrows a metadata entry in GSRAM.
    ///
    /// Callers mutate entry fields in place; the change is written
    /// straight to the GSRAM table.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    /// - `idx`: Entry slot index within the table (`0..ENTRIES_PER_TABLE`).
    ///
    /// # Returns
    ///
    /// An exclusive reference to the [`Entry`] at `(table, idx)` in GSRAM.
    fn entry_mut(&mut self, table: usize, idx: usize) -> HsmResult<&mut Entry> {
        if table >= TABLE_COUNT || idx >= ENTRIES_PER_TABLE {
            return Err(HsmError::InvalidArg);
        }
        let ptr = (Self::entry_addr(table) + idx * ENTRY_STRIDE as usize) as *mut Entry;
        // SAFETY: as `entry`, with exclusive access on the single-threaded
        // executor for the duration of the `&mut self` borrow.
        Ok(unsafe { &mut *ptr })
    }

    /// Borrows a table's block-allocator bitmap.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    ///
    /// # Returns
    ///
    /// A shared reference to the table's [`BITMAP_WORDS`]-word bitmap in
    /// GSRAM.
    fn bitmap(&self, table: usize) -> HsmResult<&[u32; BITMAP_WORDS]> {
        if table >= TABLE_COUNT {
            return Err(HsmError::InvalidArg);
        }
        let ptr = Self::bitmap_addr(table) as *const [u32; BITMAP_WORDS];
        // SAFETY: the bounds check keeps the access within table `table`'s
        // bitmap region (plain GSRAM read, 4-byte aligned).
        Ok(unsafe { &*ptr })
    }

    /// Mutably borrows a table's block-allocator bitmap.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    ///
    /// # Returns
    ///
    /// An exclusive reference to the table's [`BITMAP_WORDS`]-word bitmap
    /// in GSRAM.
    fn bitmap_mut(&mut self, table: usize) -> HsmResult<&mut [u32; BITMAP_WORDS]> {
        if table >= TABLE_COUNT {
            return Err(HsmError::InvalidArg);
        }
        let ptr = Self::bitmap_addr(table) as *mut [u32; BITMAP_WORDS];
        // SAFETY: as `bitmap`, with exclusive access on the single-threaded
        // executor for the duration of the `&mut self` borrow.
        Ok(unsafe { &mut *ptr })
    }

    /// Borrows a table's key-data blob region.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    ///
    /// # Returns
    ///
    /// A shared [`DmaBuf`] view of the table's [`BLOB_SIZE`]-byte blob in
    /// GSRAM.
    fn blob(&self, table: usize) -> HsmResult<&DmaBuf> {
        if table >= TABLE_COUNT {
            return Err(HsmError::InvalidArg);
        }
        // SAFETY: the bounds check keeps the blob within table `table`'s
        // `BLOB_SIZE` bytes of 'static GSRAM; the single-threaded executor
        // guarantees no aliasing mutation.
        Ok(unsafe {
            DmaBuf::from_raw(core::slice::from_raw_parts(
                Self::blob_addr(table) as *const u8,
                BLOB_SIZE,
            ))
        })
    }

    /// Mutably borrows a table's key-data blob region.
    ///
    /// # Parameters
    ///
    /// - `table`: Global key-vault table index.
    ///
    /// # Returns
    ///
    /// An exclusive [`DmaBuf`] view of the table's [`BLOB_SIZE`]-byte blob
    /// in GSRAM.
    fn blob_mut(&mut self, table: usize) -> HsmResult<&mut DmaBuf> {
        if table >= TABLE_COUNT {
            return Err(HsmError::InvalidArg);
        }
        // SAFETY: as `blob`, with exclusive access for the duration of the
        // `&mut self` borrow on the single-threaded executor.
        Ok(unsafe {
            DmaBuf::from_raw_mut(core::slice::from_raw_parts_mut(
                Self::blob_addr(table) as *mut u8,
                BLOB_SIZE,
            ))
        })
    }
}
