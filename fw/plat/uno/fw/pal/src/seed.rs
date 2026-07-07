// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSeedStore`] implementation for the Uno PAL.
//!
//! Device-global BKS seed material is read from the GSRAM BKS table via
//! the [`BksStore`](azihsm_fw_uno_drivers_bks_store::BksStore) driver.
//! Only one owner lineage (BKS2) is supported, so
//! [`owner_svn`](HsmSeedStore::owner_svn) is always `0` and
//! [`owner_seed`](HsmSeedStore::owner_seed) accepts only selector `0`.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSeedStore;
use azihsm_fw_uno_drivers_bks_store::BksStore;

use crate::UnoHsmPal;

/// The only supported owner-seed (BKS2) selector.
const OWNER_SVN: u64 = 0;

/// Firmware-supplied secret seed (the `BK_BOOT` masking key), a
/// device-global firmware constant used as the KBKDF key in boot-key
/// (`BKx`) derivations.  Value mirrors the reference firmware's
/// `BK_BOOT_MASKING_KEY` so derived boot keys are bit-compatible with
/// real hardware.
const FW_SEED: [u8; 48] = [
    0x5f, 0xb0, 0x8b, 0x84, 0xb2, 0x8c, 0x54, 0xc5, 0x73, 0x5c, 0x73, 0x07, 0x96, 0x99, 0xc0, 0xd0,
    0xe6, 0x11, 0x84, 0x8f, 0x65, 0xa1, 0xa5, 0x8e, 0x75, 0x72, 0x43, 0x59, 0x9e, 0x99, 0x2c, 0x88,
    0xe5, 0x73, 0x98, 0x75, 0xb4, 0x0d, 0xa1, 0x24, 0x08, 0x36, 0x70, 0xa7, 0x65, 0xa1, 0x36, 0x7d,
];

/// Unique Device Secret — the device-global root secret.  On real
/// hardware this is a fused per-device secret; the emulator has no
/// fuses, so a fixed device constant stands in.  Per-partition material
/// is derived from this with partition-distinguishing KBKDF context, so
/// a single device-wide value is correct.
const UDS: [u8; 32] = [
    0x55, 0x44, 0x53, 0x00, 0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb,
    0x68, 0xeb, 0x26, 0x99, 0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c,
];

impl HsmSeedStore for UnoHsmPal {
    /// Current firmware SVN, from BKS table entry 0.
    fn mfgr_svn(&self) -> u64 {
        BksStore::svn()
    }

    /// Owner-seed (BKS2) selector — always `0` (single lineage).
    fn owner_svn(&self) -> u64 {
        OWNER_SVN
    }

    /// Current manufacturer seed (BKS1) — BKS table entry 0.
    fn curr_mfgr_seed(&self) -> &[u8] {
        BksStore::bks1_current()
    }

    /// Current owner seed (BKS2) — the single BKS2 entry.
    fn curr_owner_seed(&self) -> &[u8] {
        BksStore::bks2()
    }

    /// Manufacturer seed (BKS1) for `svn`; `Err(SeedNotFound)` if no
    /// table entry carries that SVN.
    fn mfgr_seed(&self, svn: u64) -> HsmResult<&[u8]> {
        BksStore::bks1(svn)
    }

    /// Owner seed (BKS2) for `svn`.  Only selector `0` is provisioned;
    /// any other value returns `Err(SeedNotFound)`.
    fn owner_seed(&self, svn: u64) -> HsmResult<&[u8]> {
        if svn == OWNER_SVN {
            Ok(BksStore::bks2())
        } else {
            Err(HsmError::SeedNotFound)
        }
    }

    /// Firmware-supplied secret seed (the `BK_BOOT` masking key).
    fn fw_seed(&self) -> &[u8] {
        &FW_SEED
    }

    /// Unique Device Secret (device-global root).
    fn uds(&self) -> &[u8] {
        &UDS
    }
}
