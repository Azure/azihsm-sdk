// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire-format fixtures for the TBOR `PartInit` command.
//!
//! Pure byte-array builders — no backend / no session state — so they
//! are safe to share between the emu-only per-command tests in
//! [`crate::commands::part_init`] and the hw-eligible dispatcher-gate
//! tests in [`crate::commands::default_psk_gate`]. The layout mirrors
//! the canonical wire format in
//! `fw/core/ddi/tbor/types/src/policy.rs`.

use azihsm_ddi_tbor_types::PolicyKeyKind;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;

/// Build a 484-byte unified `PartPolicy` blob that passes
/// `azihsm_fw_hsm_core::ddi::tbor::policy::from_bytes`.  Layout mirrors
/// the canonical wire format defined in
/// `fw/core/ddi/tbor/types/src/policy.rs`: POTA + SATA trust anchors
/// are populated Ecc384 keys; SAPOTA + backing-partition keys are left
/// absent (zero `len`); flags are clear; `info` is filled.
pub fn known_good_part_policy() -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    const OFF_SATA: usize = 102;
    const OFF_FLAGS: usize = 418;
    const OFF_INFO: usize = 419;

    // Write an Ecc384 (kind 0) raw X‖Y pubkey at `off` (no SEC1 prefix).
    fn write_pubkey(bytes: &mut [u8], off: usize, fill: u8) {
        bytes[off..off + 2].copy_from_slice(&PolicyKeyKind::Ecc384.0.to_le_bytes());
        bytes[off + 2..off + 4].copy_from_slice(&96u16.to_le_bytes());
        for (i, b) in bytes[off + 4..off + 4 + 96].iter_mut().enumerate() {
            *b = (fill.wrapping_add(i as u8)) | 0x80;
        }
    }

    let mut bytes = [0u8; PART_POLICY_LEN];
    bytes[0] = 1; // version major
    bytes[1] = 0; // version minor
    write_pubkey(&mut bytes, OFF_POTA, 0x10);
    write_pubkey(&mut bytes, OFF_SATA, 0x20);
    // SAPOTA + backup-part pubkeys left absent (len 0).
    bytes[OFF_FLAGS] = 0;
    for b in bytes[OFF_INFO..OFF_INFO + 64].iter_mut() {
        *b = 0xAB;
    }
    bytes
}

/// Like [`known_good_part_policy`] but with a caller-supplied **real**
/// `POTAPubKey` (raw P-384 `X ‖ Y`, 96 bytes), so `PartFinal` can
/// validate a PTA certificate chain anchored to it.
pub fn part_policy_with_pota(pota_raw: &[u8; 96]) -> [u8; PART_POLICY_LEN] {
    const OFF_POTA: usize = 2;
    let mut bytes = known_good_part_policy();
    // POTA slot layout: kind(2) ‖ len(2) ‖ data(96); overwrite the data.
    bytes[OFF_POTA + 4..OFF_POTA + 4 + 96].copy_from_slice(pota_raw);
    bytes
}

/// Canonical `mach_seed` for `PartInit`: deterministic ramp so failing
/// fixtures are trivially identifiable in a hex dump.
pub fn mach_seed() -> [u8; MACH_SEED_LEN] {
    let mut v = [0u8; MACH_SEED_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x40 + i as u8;
    }
    v
}

/// Canonical `pota_thumbprint` for `PartInit`: deterministic pattern
/// distinct from [`mach_seed`] so a mis-plumbed field is obvious.
pub fn pota_thumbprint() -> [u8; POTA_THUMBPRINT_LEN] {
    let mut v = [0u8; POTA_THUMBPRINT_LEN];
    for (i, b) in v.iter_mut().enumerate() {
        *b = 0x80 ^ i as u8;
    }
    v
}
