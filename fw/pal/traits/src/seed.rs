// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Device-global root-of-trust seed material (the BKS table).
//!
//! [`HsmSeedStore`] exposes the device-wide backup-key seeds and their
//! selectors used as KBKDF context for partition boot-key / masking-key
//! derivations:
//!
//! - **manufacturer seed (BKS1)** — provisioned per firmware SVN; the
//!   *current* row is selected by [`mfgr_svn`](HsmSeedStore::mfgr_svn),
//!   and historical rows are addressable by SVN via
//!   [`mfgr_seed`](HsmSeedStore::mfgr_seed) (needed to recover keys
//!   masked under a previous SVN).
//! - **owner seed (BKS2)** — provisioned per device-owner lineage; the
//!   *current* row is selected by [`owner_svn`](HsmSeedStore::owner_svn).
//!   Only one lineage (selector `0`) is supported today.
//!
//! ## Why this is its own trait (not per-partition properties)
//!
//! These seeds are **device-global**, not per-partition, so the trait
//! takes no [`HsmIo`](crate::HsmIo) / partition handle.  Seeds are
//! returned as plain `&[u8]` views — consumers copy them into a freshly
//! allocated, aligned KBKDF context before use and never DMA them from
//! backing storage, so no [`DmaBuf`](crate::DmaBuf) (and hence no
//! alignment) promise is made over the seed bytes.

use crate::HsmResult;

/// Length of a single BKS seed row (BKS1 / BKS2), in bytes.
pub const BK_SEED_LEN: usize = 32;

/// Device-global root-of-trust seed material (the BKS table).
///
/// See the [module documentation](crate::seed) for the storage model
/// and the rationale for exposing these as a dedicated trait rather than
/// per-partition properties.
pub trait HsmSeedStore {
    /// Current manufacturer-seed (BKS1) selector — the firmware SVN.
    fn mfgr_svn(&self) -> u64;

    /// Current owner-seed (BKS2) selector (BKS2 lineage; always `0`
    /// today, as only one owner lineage is supported).
    fn owner_svn(&self) -> u64;

    /// Current manufacturer seed (BKS1), selected by
    /// [`mfgr_svn`](Self::mfgr_svn).  The current row always exists, so
    /// this is infallible.
    fn curr_mfgr_seed(&self) -> &[u8];

    /// Current owner seed (BKS2), selected by
    /// [`owner_svn`](Self::owner_svn).  The current row always exists,
    /// so this is infallible.
    fn curr_owner_seed(&self) -> &[u8];

    /// Manufacturer seed (BKS1) for a specific `svn` (historical
    /// lookup).  Returns [`HsmError::SeedNotFound`](crate::HsmError::SeedNotFound)
    /// if no provisioned row carries that SVN.
    fn mfgr_seed(&self, svn: u64) -> HsmResult<&[u8]>;

    /// Owner seed (BKS2) for a specific owner selector `svn`.  Returns
    /// [`HsmError::SeedNotFound`](crate::HsmError::SeedNotFound) if no
    /// provisioned row carries that selector.
    fn owner_seed(&self, svn: u64) -> HsmResult<&[u8]>;

    /// Firmware-supplied secret seed (the BK_BOOT masking key), a
    /// device-global firmware constant used as the KBKDF key in
    /// boot-key (`BKx`) derivations.  Always present.
    fn fw_seed(&self) -> &[u8];

    /// Unique Device Secret — the device-global root secret used as the
    /// KBKDF key when deriving per-partition material (e.g. UMS), with
    /// the partition-distinguishing inputs supplied as KBKDF context.
    /// Sensitive; always present.
    fn uds(&self) -> &[u8];
}
