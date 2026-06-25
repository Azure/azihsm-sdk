// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GSRAM-backed BKS table accessor for the Uno platform.
//!
//! The BKS table is device-global root-of-trust seed material populated
//! by the secure platform (SP) into a fixed GSRAM region (mirroring the
//! reference firmware's `GsRamMemMap::bks_table`).  This driver owns the
//! SoC-specific knowledge of where that table lives and its packed
//! on-storage layout, so the PAL's [`HsmSeedStore`] implementation can
//! stay free of `reg_soc` dependencies.
//!
//! The table holds 12 packed 41-byte entries:
//!   * entry `[0]`     — current BKS1 (`entry[0].svn` = current FW SVN)
//!   * entry `[1..10]` — last ten SVNs' BKS1 (history)
//!   * entry `[11]`    — the single BKS2 (`bks2_id` is always 0)
//!
//! Each entry is byte-packed `{ valid:u8, svn:[u8;8], bks:[u8;32] }` and
//! not word-aligned, so it is modeled in RDL as an opaque byte region;
//! the typed layout lives here.  Seed bytes are returned as `&[u8]`
//! views — callers copy them into an aligned KBKDF context before use.

#![no_std]
#![allow(unsafe_code)]

mod bks_store;

pub use bks_store::BksStore;
pub use bks_store::BK_SEED_LEN;
pub use bks_store::NUM_BKS_ENTRIES;
