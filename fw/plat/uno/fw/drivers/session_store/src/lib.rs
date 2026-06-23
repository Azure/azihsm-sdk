// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM-backed per-partition session-table storage for Uno firmware.

#![no_std]
#![allow(unsafe_code)]

use azihsm_fw_uno_drivers_part_store::NUM_PARTITIONS;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;

pub use azihsm_fw_uno_session::SessionTable;

/// GSRAM byte offset of the session-store region.
///
/// Placed immediately after the 65-entry partition table
/// (`PART_STORE` ends at `0xBB000 + 65 * 0x200 = 0xC3200`) and before the
/// key vault (`KEY_VAULT @ 0xEBC00`).  8-byte aligned for the `u64` fields.
const SESSION_STORE_OFFSET: u32 = 0xC4000;
const SESSION_STORE_BASE: u32 = IO_GSRAM_BASE + SESSION_STORE_OFFSET;

/// Compile-time guarantee the session store fits between the partition table
/// and the key vault.
const _SESSION_STORE_FITS: () = assert!(
    SESSION_STORE_OFFSET >= 0xC3200
        && (SESSION_STORE_OFFSET as usize)
            + NUM_PARTITIONS * core::mem::size_of::<SessionTable>()
            <= 0xEBC00,
    "session store must fit between PART_STORE and KEY_VAULT"
);

/// Zero-sized GSRAM accessor for the `[SessionTable; NUM_PARTITIONS]` store.
///
/// Mirrors [`azihsm_fw_uno_drivers_part_store::PartTable`]: every entry is
/// addressed directly in GSRAM, so this handle carries no state.
pub struct SessionStore;

impl SessionStore {
    #[inline]
    fn ptr(pid: usize) -> *mut SessionTable {
        debug_assert!(pid < NUM_PARTITIONS);
        (SESSION_STORE_BASE as usize + pid * core::mem::size_of::<SessionTable>())
            as *mut SessionTable
    }

    /// Shared reference to partition `pid`'s session table.
    #[inline]
    pub fn table(pid: usize) -> &'static SessionTable {
        // SAFETY: `pid < NUM_PARTITIONS` keeps the entry within the reserved
        // session-store GSRAM region; the single-threaded executor guarantees
        // no aliasing for the (non-escaping) borrow.
        unsafe { &*Self::ptr(pid) }
    }

    /// Exclusive reference to partition `pid`'s session table.
    #[inline]
    pub fn table_mut(pid: usize) -> &'static mut SessionTable {
        // SAFETY: as `table`; the borrow does not escape the calling accessor.
        unsafe { &mut *Self::ptr(pid) }
    }

    /// Zero every partition's session table (clean slate).  Called once during
    /// PAL init; GSRAM is not guaranteed zeroed.
    pub fn init_default() {
        // SAFETY: writes exactly `NUM_PARTITIONS` contiguous `SessionTable`s
        // within the reserved session-store region.
        unsafe {
            core::ptr::write_bytes(Self::ptr(0), 0, NUM_PARTITIONS);
        }
    }

    /// Clear one partition's session table (on free / new incarnation).
    pub fn clear(pid: usize) {
        // SAFETY: single in-bounds entry.
        unsafe {
            core::ptr::write_bytes(Self::ptr(pid), 0, 1);
        }
    }
}
