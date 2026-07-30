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

/// Verifies that a successful PartInit response contains both PTA artifacts.
macro_rules! assert_part_init_artifacts_present {
    ($resp:expr) => {
        assert!(
            !$resp.pta_csr.is_empty(),
            "PTACSR must be present after successful PartInit"
        );
        assert!(
            !$resp.pta_report.is_empty(),
            "PTAReport must be present after successful PartInit"
        );
    };
}

#[test]
fn part_init_with_sata() {
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
        .expect("PartInit with SATA thumbprint must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_sapota() {
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
        .expect("PartInit with SATA and SAPOTA thumbprints must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_modified_sata_thumbprint_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();

    // Modify bytes at both ends so this test does not accidentally exercise
    // only a prefix or suffix of the serialized thumbprint.
    sata[0] ^= 0x80;
    sata[sata.len() - 1] ^= 0x01;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with a modified valid SATA thumbprint must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_modified_sapota_thumbprint_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sapota = [0x33u8; 48];

    // Modify multiple positions to ensure the complete SAPOTA value can be
    // transported rather than only accepting one known test pattern.
    sapota[0] = 0xA5;
    sapota[sapota.len() / 2] = 0x5A;
    sapota[sapota.len() - 1] = 0xC3;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with a modified valid SAPOTA thumbprint must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_distinct_sata_and_sapota_thumbprints_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0x55u8; 48];
    let sapota = [0xAAu8; 48];

    assert_ne!(
        sata, sapota,
        "test setup requires distinct SATA and SAPOTA thumbprints"
    );

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with distinct SATA and SAPOTA thumbprints must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_matching_sata_and_sapota_thumbprints_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // SATA and SAPOTA identify different roles, but PartInit should transport
    // the supplied thumbprints rather than requiring their byte values to be
    // different.
    let shared_thumbprint = [0x6Cu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &shared_thumbprint,
            Some(&shared_thumbprint),
        )
        .expect("PartInit must accept matching SATA and SAPOTA byte values");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_boundary_pattern_sd_thumbprints_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // Exercise both ends of the byte range. These are still correctly sized
    // opaque thumbprint values.
    let sata = [0x00u8; 48];
    let sapota = [0xFFu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit must accept correctly sized SD thumbprint patterns");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_with_modified_merged_sd_inputs_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut seed = mach_seed();
    seed[0] ^= 0x20;
    seed[seed.len() - 1] ^= 0x04;

    let policy = known_good_part_policy();

    let mut pota = pota_thumbprint();
    pota[0] ^= 0x10;
    pota[pota.len() - 1] ^= 0x02;

    let mut sata = sata_thumbprint();
    sata[0] ^= 0x40;
    sata[sata.len() - 1] ^= 0x08;

    let mut sapota = [0x33u8; 48];
    sapota[0] ^= 0x81;
    sapota[sapota.len() - 1] ^= 0x18;

    let resp = ctx
        .part_init_sd(&session, &seed, &policy, &pota, &sata, Some(&sapota))
        .expect("PartInit with independently modified merged SD inputs must succeed");

    assert_part_init_artifacts_present!(resp);
}

#[test]
fn part_init_sd_without_sapota_still_returns_both_artifacts_emu() {
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
        .expect("SAPOTA must remain optional during PartInit");

    assert_part_init_artifacts_present!(resp);

    assert!(
        resp.pta_csr.len() > 1,
        "PTACSR must contain encoded data, not only an empty placeholder"
    );
    assert!(
        resp.pta_report.len() > 1,
        "PTAReport must contain encoded data, not only an empty placeholder"
    );
}

/// Verifies that PartInit accepts different valid SATA thumbprints across clean device states.
#[test]
fn part_init_with_different_sata_thumbprints_emu() {
    let ctx = TestCtx::new();

    let mut sata_a = sata_thumbprint();
    sata_a[0] ^= 0x01;

    let mut sata_b = sata_thumbprint();
    sata_b[0] ^= 0x02;

    ctx.erase().expect("erase before first SATA PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp_a = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_a,
            None,
        )
        .expect("PartInit with first SATA thumbprint");

    assert!(!resp_a.pta_csr.is_empty(), "first PTACSR must be non-empty");
    assert!(
        !resp_a.pta_report.is_empty(),
        "first PTAReport must be non-empty"
    );

    ctx.erase().expect("erase before second SATA PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp_b = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_b,
            None,
        )
        .expect("PartInit with second SATA thumbprint");

    assert!(
        !resp_b.pta_csr.is_empty(),
        "second PTACSR must be non-empty"
    );
    assert!(
        !resp_b.pta_report.is_empty(),
        "second PTAReport must be non-empty"
    );
}

/// Verifies that PartInit accepts different valid SAPOTA thumbprints across clean device states.
#[test]
fn part_init_with_different_sapota_thumbprints_emu() {
    let ctx = TestCtx::new();

    let sapota_a = [0x33u8; 48];
    let sapota_b = [0x66u8; 48];

    ctx.erase().expect("erase before first SAPOTA PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp_a = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota_a),
        )
        .expect("PartInit with first SAPOTA thumbprint");

    assert!(!resp_a.pta_csr.is_empty(), "first PTACSR must be non-empty");
    assert!(
        !resp_a.pta_report.is_empty(),
        "first PTAReport must be non-empty"
    );

    ctx.erase().expect("erase before second SAPOTA PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let resp_b = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota_b),
        )
        .expect("PartInit with second SAPOTA thumbprint");

    assert!(
        !resp_b.pta_csr.is_empty(),
        "second PTACSR must be non-empty"
    );
    assert!(
        !resp_b.pta_report.is_empty(),
        "second PTAReport must be non-empty"
    );
}

/// Verifies that SAPOTA is optional and PartInit succeeds both with and without it.
#[test]
fn part_init_sapota_is_optional_emu() {
    let ctx = TestCtx::new();

    ctx.erase().expect("erase before PartInit without SAPOTA");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let without_sapota = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("PartInit without SAPOTA");

    assert!(
        !without_sapota.pta_csr.is_empty(),
        "PTACSR must be non-empty without SAPOTA"
    );
    assert!(
        !without_sapota.pta_report.is_empty(),
        "PTAReport must be non-empty without SAPOTA"
    );

    ctx.erase().expect("erase before PartInit with SAPOTA");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let sapota = [0x33u8; 48];

    let with_sapota = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with SAPOTA");

    assert!(
        !with_sapota.pta_csr.is_empty(),
        "PTACSR must be non-empty with SAPOTA"
    );
    assert!(
        !with_sapota.pta_report.is_empty(),
        "PTAReport must be non-empty with SAPOTA"
    );
}

/// Verifies that PartInit accepts a correctly sized all-zero SATA thumbprint.
#[test]
fn part_init_with_all_zero_sata_thumbprint_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0x00u8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with all-zero SATA thumbprint");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that PartInit accepts correctly sized all-0xFF SATA and SAPOTA thumbprints.
#[test]
fn part_init_with_all_ff_sata_and_sapota_thumbprints_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0xFFu8; 48];
    let sapota = [0xFFu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with all-0xFF SATA and SAPOTA thumbprints");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that independent single-byte changes to SATA and SAPOTA thumbprints are accepted.
#[test]
fn part_init_accepts_single_byte_changes_in_each_sd_thumbprint_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();
    sata[17] ^= 0x40;

    let mut sapota = [0x33u8; 48];
    sapota[31] ^= 0x80;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with independently modified SD thumbprints");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that PartInit succeeds again after the device is erased and re-bootstrapped.
#[test]
fn part_init_sd_succeeds_again_after_erase_and_rebootstrap_emu() {
    let ctx = TestCtx::new();
    let sapota = [0x33u8; 48];

    ctx.erase().expect("erase before first PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let first = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("first PartInit");

    assert!(!first.pta_csr.is_empty(), "first PTACSR must be non-empty");
    assert!(
        !first.pta_report.is_empty(),
        "first PTAReport must be non-empty"
    );

    ctx.erase().expect("erase after first PartInit");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let second = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("second PartInit after erase and re-bootstrap");

    assert!(
        !second.pta_csr.is_empty(),
        "second PTACSR must be non-empty"
    );
    assert!(
        !second.pta_report.is_empty(),
        "second PTAReport must be non-empty"
    );
}

/// Verifies that PartInit accepts an all-zero SATA thumbprint when SAPOTA is absent.
#[test]
fn sd_config_all_zero_sata_without_sapota_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0x00u8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with all-zero SATA thumbprint must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that PartInit accepts an all-0xFF SATA thumbprint when SAPOTA is absent.
#[test]
fn sd_config_all_ff_sata_without_sapota_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0xFFu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with all-0xFF SATA thumbprint must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that PartInit accepts all-zero SATA and SAPOTA thumbprints together.
#[test]
fn sd_config_all_zero_sata_and_sapota_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0x00u8; 48];
    let sapota = [0x00u8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with all-zero SATA and SAPOTA thumbprints must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that PartInit accepts all-0xFF SATA and SAPOTA thumbprints together.
#[test]
fn sd_config_all_ff_sata_and_sapota_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0xFFu8; 48];
    let sapota = [0xFFu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with all-0xFF SATA and SAPOTA thumbprints must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that SATA and SAPOTA may contain identical opaque thumbprint values.
#[test]
fn sd_config_matching_sata_and_sapota_values_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let shared_thumbprint = [0x6Cu8; 48];

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &shared_thumbprint,
            Some(&shared_thumbprint),
        )
        .expect("PartInit with matching SATA and SAPOTA values must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that distinct SATA and SAPOTA values are accepted independently.
#[test]
fn sd_config_distinct_sata_and_sapota_values_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let sata = [0x55u8; 48];
    let sapota = [0xAAu8; 48];

    assert_ne!(
        sata, sapota,
        "test setup requires distinct SATA and SAPOTA values"
    );

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with distinct SATA and SAPOTA values must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that alternating-byte SATA and SAPOTA thumbprints are accepted.
#[test]
fn sd_config_alternating_sata_and_sapota_patterns_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = [0u8; 48];
    let mut sapota = [0u8; 48];

    for index in 0..48 {
        sata[index] = if index % 2 == 0 { 0xAA } else { 0x55 };
        sapota[index] = if index % 2 == 0 { 0x55 } else { 0xAA };
    }

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with alternating SD thumbprint patterns must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that ascending and descending SD thumbprint byte sequences are accepted.
#[test]
fn sd_config_sequential_sata_and_sapota_patterns_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = [0u8; 48];
    let mut sapota = [0u8; 48];

    for index in 0..48 {
        sata[index] = index as u8;
        sapota[index] = (47 - index) as u8;
    }

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with sequential SD thumbprint patterns must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SATA thumbprint differing only in its first byte is accepted.
#[test]
fn sd_config_sata_first_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();
    sata[0] ^= 0x80;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with modified first SATA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SATA thumbprint differing only in its middle byte is accepted.
#[test]
fn sd_config_sata_middle_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();
    let middle = sata.len() / 2;
    sata[middle] ^= 0x40;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with modified middle SATA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SATA thumbprint differing only in its final byte is accepted.
#[test]
fn sd_config_sata_last_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();
    let last = sata.len() - 1;
    sata[last] ^= 0x01;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            None,
        )
        .expect("PartInit with modified final SATA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SAPOTA thumbprint differing only in its first byte is accepted.
#[test]
fn sd_config_sapota_first_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sapota = [0x33u8; 48];
    sapota[0] ^= 0x80;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with modified first SAPOTA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SAPOTA thumbprint differing only in its middle byte is accepted.
#[test]
fn sd_config_sapota_middle_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sapota = [0x33u8; 48];
    let middle = sapota.len() / 2;
    sapota[middle] ^= 0x40;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with modified middle SAPOTA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that a SAPOTA thumbprint differing only in its final byte is accepted.
#[test]
fn sd_config_sapota_last_byte_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sapota = [0x33u8; 48];
    let last = sapota.len() - 1;
    sapota[last] ^= 0x01;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            Some(&sapota),
        )
        .expect("PartInit with modified final SAPOTA byte must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that changing both ends of both SD thumbprints is accepted.
#[test]
fn sd_config_sata_and_sapota_endpoint_changes_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut sata = sata_thumbprint();
    let sata_last = sata.len() - 1;
    sata[0] ^= 0xA5;
    sata[sata_last] ^= 0x5A;

    let mut sapota = [0x33u8; 48];
    let sapota_last = sapota.len() - 1;
    sapota[0] ^= 0x3C;
    sapota[sapota_last] ^= 0xC3;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with modified SD thumbprint endpoints must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that independently modified POTA, SATA, and SAPOTA values are accepted together.
#[test]
fn sd_config_all_thumbprints_independently_modified_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let mut pota = pota_thumbprint();
    let pota_last = pota.len() - 1;
    pota[0] ^= 0x10;
    pota[pota_last] ^= 0x01;

    let mut sata = sata_thumbprint();
    let sata_last = sata.len() - 1;
    sata[0] ^= 0x20;
    sata[sata_last] ^= 0x02;

    let mut sapota = [0x33u8; 48];
    let sapota_last = sapota.len() - 1;
    sapota[0] ^= 0x40;
    sapota[sapota_last] ^= 0x04;

    let resp = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota,
            &sata,
            Some(&sapota),
        )
        .expect("PartInit with independently modified thumbprints must succeed");

    assert!(!resp.pta_csr.is_empty(), "PTACSR must be non-empty");
    assert!(!resp.pta_report.is_empty(), "PTAReport must be non-empty");
}

/// Verifies that the returned CSR and report contain more than placeholder bytes.
#[test]
fn sd_config_response_artifacts_have_encoded_content_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

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
        .expect("PartInit with complete SD configuration must succeed");

    assert!(
        resp.pta_csr.len() > 1,
        "PTACSR must contain encoded content"
    );
    assert!(
        resp.pta_report.len() > 1,
        "PTAReport must contain encoded content"
    );
}

/// Verifies that the CSR begins with a DER SEQUENCE tag.
#[test]
fn sd_config_pta_csr_has_der_sequence_prefix_emu() {
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
        .expect("PartInit must return a PTA CSR");

    assert!(
        !resp.pta_csr.is_empty(),
        "PTACSR must contain at least the DER tag"
    );
    assert_eq!(
        resp.pta_csr[0], 0x30,
        "PTACSR must begin with a DER SEQUENCE tag"
    );
}

/// Verifies that omitting SAPOTA still returns both required PTA artifacts.
#[test]
fn sd_config_without_sapota_returns_complete_response_emu() {
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
        .expect("PartInit without SAPOTA must succeed");

    assert!(
        !resp.pta_csr.is_empty(),
        "PTACSR must be returned without SAPOTA"
    );
    assert!(
        !resp.pta_report.is_empty(),
        "PTAReport must be returned without SAPOTA"
    );
}

/// Verifies that supplying SAPOTA returns both required PTA artifacts.
#[test]
fn sd_config_with_sapota_returns_complete_response_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

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
        .expect("PartInit with SAPOTA must succeed");

    assert!(
        !resp.pta_csr.is_empty(),
        "PTACSR must be returned with SAPOTA"
    );
    assert!(
        !resp.pta_report.is_empty(),
        "PTAReport must be returned with SAPOTA"
    );
}

/// Verifies that PartInit cannot be executed twice without resetting the device state.
#[test]
fn second_part_init_without_erase_is_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.part_init_sd(
        &session,
        &mach_seed(),
        &known_good_part_policy(),
        &pota_thumbprint(),
        &sata_thumbprint(),
        None,
    )
    .expect("first PartInit must succeed");

    let err = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect_err("second PartInit without erase must be rejected");

    eprintln!("second PartInit rejection: {err:?}");
}

/// Verifies that a session created before erase cannot be reused for PartInit.
#[test]
fn part_init_with_stale_session_after_erase_is_rejected_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    ctx.erase().expect("erase must succeed");

    let err = ctx
        .part_init_sd(
            &session,
            &mach_seed(),
            &known_good_part_policy(),
            &pota_thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect_err("PartInit with a session created before erase must be rejected");

    eprintln!("stale-session PartInit rejection: {err:?}");
}
