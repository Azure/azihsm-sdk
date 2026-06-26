// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain parameter tests for the merged `PartInit`.
//!
//! The unified PartPolicy and the SATA / SAPOTA thumbprint request
//! params are carried by PartInit, but the security-domain *local
//! masking keys* are deliberately NOT derived here — that is deferred
//! to a future part-final command (which binds them to the
//! POTA-endorsed PTA cert chain).  These tests therefore only assert
//! that PartInit accepts the merged SD params end-to-end.
//!
//! * [`part_init_with_sata_emu`] — PartInit with an explicit SATA
//!   thumbprint (no SAPOTA) succeeds.
//! * [`part_init_with_sapota_emu`] — PartInit additionally carrying a
//!   SAPOTA thumbprint succeeds.

use super::bootstrap_rotated_co;
use super::known_good_part_policy;
use super::mach_seed;
use super::pota_thumbprint;
use super::sata_thumbprint;
use super::ROTATED_CO_PSK;
use crate::harness::TestCtx;

#[test]
fn part_init_with_sata_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("PartInit with SATA thumbprint");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

#[test]
fn part_init_with_sapota_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // A distinct 48-byte SAPOTA thumbprint.
    let sapota = [0x33u8; 48];
    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with SAPOTA thumbprint");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}
