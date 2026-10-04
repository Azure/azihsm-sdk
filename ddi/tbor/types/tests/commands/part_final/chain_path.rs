// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartFinal` chain-integrity rejects.
//!
//! These are the cases that need a **well-formed but wrong** PTA chain, so
//! they are the tests that must reach `validate_pta_chain` with something
//! for it to reject: a chain not anchored to the policy's POTA key, a chain
//! whose terminal certificate carries the wrong PTA key, and chains whose
//! terminal PTA certificate carries the right key but violates the pinned
//! PTA profile (wrong subject DN or Subject Key Identifier).
//!
//! They assert the specific `TborStatus` rather than calling bare
//! `expect_err`. That matters more than it looks: these tests began life
//! `#[cfg(feature = "emu")]` with a bare `expect_err`, which passed
//! happily while the out-of-band transport was returning a DMA fault —
//! failing for a reason that had nothing to do with the chain.
//!
//! Certificates travel **out of band**, and both transports now
//! implement that: `ddi/emu` writes the metadata page directly, and
//! `ddi/nix` hands the items to the driver's data-transfer ioctl, which
//! DMA-maps them and builds the page in the kernel. So these run on
//! `emu` **and hardware**.
//!
//! Everything else about `PartFinal` — the happy path, backup restore,
//! lifecycle and role gates — lives in [`super`], which also carries a
//! real chain on both backends. The gates that fire *before* the chain
//! walk live in [`super::fw_rejects`].

use azihsm_ddi_tbor_test_harness::assertions::assert_fw_rejects;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain_constrained_root;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain_wrong_skid;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain_wrong_subject;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_types::TborStatus;

use super::*;
use crate::commands::part_init::part_policy_with_pota;

/// A PTA chain that is not anchored to the policy `POTAPubKey` must be
/// rejected: here the chain is rooted at a different CA than the policy's
/// POTA key, so the anchor requirement is never met.
#[test]
fn part_final_reject_unanchored_chain() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Certify the (correct) PTA key under a rogue CA that is not the
    // policy POTA anchor.
    let rogue = CaKey::generate();
    let chain = make_pta_chain(&rogue, &pta_pub_from_csr(&init.pta_csr));

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a chain not anchored to the policy POTA must be rejected");
    // Assert the specific status: a bare `expect_err` would also accept
    // a transport/DMA failure and pass for the wrong reason.
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A POTA-anchored chain whose terminal (PTA) certificate carries a key
/// other than the partition PTA key must be rejected
/// (`PartFinalPtaMismatch`).
#[test]
fn part_final_reject_pta_mismatch() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Correctly anchored to POTA, but the PTA cert certifies the wrong
    // public key (not the partition's PTA).
    let wrong_pta = CaKey::generate();
    let chain = make_pta_chain(&pota, &wrong_pta.sec1_pub());

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA cert carrying a non-partition key must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
}

/// A POTA-anchored chain carrying the correct partition PTA key, but whose
/// terminal PTA certificate has a subject DN other than the deterministic
/// single-`commonName(64)` profile, must be rejected: the firmware stamps
/// that exact subject as the issuer of its on-demand slot-2 PID leaf, so a
/// divergent subject would leave the PID leaf unable to chain to the PTA.
#[test]
fn part_final_reject_pta_wrong_subject() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Correct POTA anchor and partition PTA key, but a non-conformant
    // subject DN.
    let chain = make_pta_chain_wrong_subject(&pota, &pta_pub_from_csr(&init.pta_csr));

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA cert with a non-profile subject must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
}

/// A POTA-anchored chain carrying the correct partition PTA key and the
/// conformant subject, but whose terminal PTA certificate's Subject Key
/// Identifier is not SHA-1 of the SEC1 PTA key, must be rejected: the
/// firmware stamps that SKID as the slot-2 PID leaf's authority key
/// identifier, so a divergent SKID breaks AKID↔SKID chaining.
#[test]
fn part_final_reject_pta_wrong_skid() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    let chain = make_pta_chain_wrong_skid(&pota, &pta_pub_from_csr(&init.pta_csr));

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA cert with a non-profile SKID must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
}

/// A POTA-anchored chain carrying the correct partition PTA key and a fully
/// conformant PTA profile, but whose root CA constrains the path length to
/// zero, must be rejected: the terminal PTA is validated as an *issuing* CA
/// (it must later sign the on-demand slot-2 PID leaf), so a root that
/// forbids any further CA beneath it leaves no path-length budget for the
/// PTA. Accepting it would finalize a partition whose eventual
/// POTA→PTA→PID evidence chain could never validate.
#[test]
fn part_final_reject_pta_constrained_ancestor() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let init = ctx
        .part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Correct POTA anchor, partition PTA key, and PTA profile, but the root
    // CA has `pathLenConstraint == 0`, so the PTA cannot act as an issuing
    // CA for the slot-2 PID leaf.
    let chain = make_pta_chain_constrained_root(&pota, &pta_pub_from_csr(&init.pta_csr));

    let err = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA under a path-length-constrained root must be rejected");
    assert_fw_rejects(&err, TborStatus::X509PathLenExceeded);
}
