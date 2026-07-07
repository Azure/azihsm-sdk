// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BKS table: typed packed GSRAM layout and the [`BksStore`] accessor.

use core::mem::size_of;

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_uno_reg_soc::io_gsram::BKS_TABLE_COUNT;
use azihsm_fw_uno_reg_soc::io_gsram::BKS_TABLE_OFFSET;
use azihsm_fw_uno_reg_soc::io_gsram::BKS_TABLE_STRIDE;
use azihsm_fw_uno_reg_soc::io_gsram::IO_GSRAM_BASE;

/// Length of a single BKS seed (`bks` field), in bytes.
pub const BK_SEED_LEN: usize = 32;

/// Number of entries in the BKS table.
pub const NUM_BKS_ENTRIES: usize = 12;

/// Index of the current BKS1 entry (also carries the current FW SVN).
const CURRENT_BKS1: usize = 0;

/// Index of the single BKS2 entry (last row of the table).
const BKS2: usize = NUM_BKS_ENTRIES - 1;

/// Packed mirror of the reference firmware's `BksTableEntry` (41 bytes,
/// `#[repr(C)]`, all byte fields so alignment is 1 and there is no
/// padding — byte-identical to the SP-populated GSRAM layout).
#[repr(C)]
#[derive(Clone, Copy)]
struct BksEntry {
    /// Entry valid flag.
    valid: u8,
    /// SVN for this entry (little-endian u64).
    svn: [u8; 8],
    /// 256-bit backup seed.
    bks: [u8; BK_SEED_LEN],
}

// The packed entry must match the reference 41-byte layout, and the
// generated RDL constants must agree with this typed view.
const _: () = assert!(size_of::<BksEntry>() == 41);
const _: () = assert!(BKS_TABLE_STRIDE as usize == size_of::<BksEntry>());
const _: () = assert!(BKS_TABLE_COUNT as usize == NUM_BKS_ENTRIES);

/// Absolute GSRAM base address of BKS table entry 0.
const BKS_BASE: usize = (IO_GSRAM_BASE + BKS_TABLE_OFFSET) as usize;

/// Device-global accessor for the GSRAM BKS table.
///
/// The table is read-only device material populated by the secure
/// platform; all accessors are zero-cost views into GSRAM.
pub struct BksStore;

impl BksStore {
    /// Returns the 12-entry table as a typed slice over GSRAM.
    #[inline]
    fn table() -> &'static [BksEntry; NUM_BKS_ENTRIES] {
        // SAFETY: `BKS_BASE` points at the SP-populated, read-only BKS
        // region whose size and stride are const-asserted to match
        // `[BksEntry; NUM_BKS_ENTRIES]`.  GSRAM is plain shared SRAM, so
        // a non-volatile reference is sound.
        unsafe { &*(BKS_BASE as *const [BksEntry; NUM_BKS_ENTRIES]) }
    }

    /// Current firmware SVN — `entry[0].svn` decoded little-endian.
    #[inline(never)]
    pub fn svn() -> u64 {
        u64::from_le_bytes(Self::table()[CURRENT_BKS1].svn)
    }

    /// Current BKS1 seed — `entry[0].bks`.
    #[inline(never)]
    pub fn bks1_current() -> &'static [u8] {
        &Self::table()[CURRENT_BKS1].bks[..]
    }

    /// BKS1 seed for a specific `svn`: scans the BKS1 entries (the
    /// current entry plus the SVN history, i.e. all rows *except* the
    /// trailing BKS2 row) for a **valid** entry whose `svn` matches.
    /// Returns [`HsmError::SeedNotFound`] if no valid BKS1 entry carries
    /// that SVN.
    #[inline(never)]
    pub fn bks1(svn: u64) -> HsmResult<&'static [u8]> {
        let target = svn.to_le_bytes();
        Self::table()[CURRENT_BKS1..BKS2]
            .iter()
            .find(|e| e.valid != 0 && e.svn == target)
            .map(|e| &e.bks[..])
            .ok_or(HsmError::SeedNotFound)
    }

    /// The single BKS2 seed — `entry[11].bks`.  `bks2_id` is always 0,
    /// so there is no index parameter.
    #[inline(never)]
    pub fn bks2() -> &'static [u8] {
        &Self::table()[BKS2].bks[..]
    }
}
