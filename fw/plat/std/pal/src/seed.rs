// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! [`HsmSeedStore`] implementation for the std PAL.
//!
//! The std PAL emulator models a single firmware SVN and a single owner
//! lineage, so it provisions exactly one manufacturer-seed (BKS1) row
//! and one owner-seed (BKS2) row.  The bytes are taken from the prior
//! reference firmware so derived masking keys are bit-compatible with
//! persisted `Masked_BK_BOOT` blobs across the emulator and real
//! hardware.

use azihsm_fw_hsm_pal_traits::HsmError;
use azihsm_fw_hsm_pal_traits::HsmResult;
use azihsm_fw_hsm_pal_traits::HsmSeedStore;
use azihsm_fw_hsm_pal_traits::BK_SEED_LEN;

use crate::StdHsmPal;

/// Hardcoded std PAL firmware SVN (the only provisioned BKS1 selector).
const STD_SVN: u64 = 0;

/// The only supported owner-seed (BKS2) selector.
const STD_OWNER_SVN: u64 = 0;

/// Hardcoded std PAL manufacturer seed (BKS1) for SVN 0.
const STD_MFGR_SEED_ROW0: [u8; BK_SEED_LEN] = [
    0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb, 0x68, 0xeb, 0x26, 0x99,
    0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c, 0x21, 0x02, 0xb0, 0xac,
];

/// Hardcoded std PAL owner seed (BKS2) for owner selector 0.
const STD_OWNER_SEED_ROW0: [u8; BK_SEED_LEN] = [
    0xad, 0x1a, 0x17, 0xe9, 0xed, 0x38, 0x27, 0x5e, 0x8b, 0x30, 0x5d, 0xb8, 0x19, 0x0f, 0x82, 0xb6,
    0x2d, 0xa2, 0x5a, 0xc6, 0xf0, 0x70, 0xa3, 0xe1, 0x75, 0x9c, 0x61, 0x92, 0xcc, 0xf4, 0x19, 0xa3,
];

/// Firmware-supplied secret seed (`fw_seed`), a device-global firmware
/// constant used as the KBKDF key in boot-key (`BKx`) derivations.
///
/// Must match the Uno PAL's `FW_SEED` (the reference firmware's
/// `BK_BOOT_MASKING_KEY`): `fw_seed` is a firmware constant, not
/// hardware-fused, so a shared value keeps `BKx` derivation — and thus
/// `Masked_BK_BOOT` masking/unmasking — bit-compatible across the
/// emulator and real hardware.
const STD_FW_SEED48: [u8; 48] = [
    0x5f, 0xb0, 0x8b, 0x84, 0xb2, 0x8c, 0x54, 0xc5, 0x73, 0x5c, 0x73, 0x07, 0x96, 0x99, 0xc0, 0xd0,
    0xe6, 0x11, 0x84, 0x8f, 0x65, 0xa1, 0xa5, 0x8e, 0x75, 0x72, 0x43, 0x59, 0x9e, 0x99, 0x2c, 0x88,
    0xe5, 0x73, 0x98, 0x75, 0xb4, 0x0d, 0xa1, 0x24, 0x08, 0x36, 0x70, 0xa7, 0x65, 0xa1, 0x36, 0x7d,
];

/// Unique Device Secret — the device-global root secret.  The std PAL
/// has no fused per-device secret, so a fixed device constant stands
/// in.  Per-partition material is derived from this with
/// partition-distinguishing KBKDF context, so a single device-wide
/// value is correct.
const STD_UDS: [u8; 32] = [
    0x55, 0x44, 0x53, 0x00, 0x9b, 0x4e, 0x4e, 0xb7, 0xad, 0xab, 0xdc, 0xd6, 0xb4, 0xd5, 0x07, 0xeb,
    0x68, 0xeb, 0x26, 0x99, 0x2a, 0xbb, 0xca, 0xb5, 0x5c, 0xfb, 0x77, 0x3b, 0xc4, 0xd0, 0xa8, 0x8c,
];

impl HsmSeedStore for StdHsmPal {
    fn mfgr_svn(&self) -> u64 {
        STD_SVN
    }

    fn owner_svn(&self) -> u64 {
        STD_OWNER_SVN
    }

    fn curr_mfgr_seed(&self) -> &[u8] {
        &STD_MFGR_SEED_ROW0
    }

    fn curr_owner_seed(&self) -> &[u8] {
        &STD_OWNER_SEED_ROW0
    }

    fn mfgr_seed(&self, svn: u64) -> HsmResult<&[u8]> {
        if svn == STD_SVN {
            Ok(&STD_MFGR_SEED_ROW0)
        } else {
            Err(HsmError::SeedNotFound)
        }
    }

    fn owner_seed(&self, svn: u64) -> HsmResult<&[u8]> {
        if svn == STD_OWNER_SVN {
            Ok(&STD_OWNER_SEED_ROW0)
        } else {
            Err(HsmError::SeedNotFound)
        }
    }

    fn fw_seed(&self) -> &[u8] {
        &STD_FW_SEED48
    }

    fn uds(&self) -> &[u8] {
        &STD_UDS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_selectors_are_zero() {
        let pal = StdHsmPal::default();
        assert_eq!(pal.mfgr_svn(), 0);
        assert_eq!(pal.owner_svn(), 0);
    }

    #[test]
    fn current_seeds_return_provisioned_rows() {
        let pal = StdHsmPal::default();
        assert_eq!(pal.curr_mfgr_seed(), &STD_MFGR_SEED_ROW0[..]);
        assert_eq!(pal.curr_owner_seed(), &STD_OWNER_SEED_ROW0[..]);
    }

    #[test]
    fn provisioned_selectors_resolve() {
        let pal = StdHsmPal::default();
        assert_eq!(pal.mfgr_seed(0).unwrap(), &STD_MFGR_SEED_ROW0[..]);
        assert_eq!(pal.owner_seed(0).unwrap(), &STD_OWNER_SEED_ROW0[..]);
    }

    #[test]
    fn unprovisioned_selectors_return_not_found() {
        let pal = StdHsmPal::default();
        for svn in [1u64, 5, 63] {
            assert!(matches!(pal.mfgr_seed(svn), Err(HsmError::SeedNotFound)));
            assert!(matches!(pal.owner_seed(svn), Err(HsmError::SeedNotFound)));
        }
    }
}
