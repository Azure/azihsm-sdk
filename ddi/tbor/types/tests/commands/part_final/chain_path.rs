// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `PartFinal` chain-integrity rejects.
//!
//! These are the two cases that need a **well-formed but wrong** PTA
//! chain, so they are the only tests that must reach
//! `validate_pta_chain` with something for it to reject: a chain not
//! anchored to the policy's POTA key, and a chain whose terminal
//! certificate carries the wrong PTA key.
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

use azihsm_ddi_tbor_types::TborStatus;

use super::*;
use crate::commands::part_init::part_policy_with_pota;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::PtaChain;
use crate::harness::SessionHandshake;

/// Run `PartInit` on `session` and issue the resulting PTA chain: read
/// the PTA public key from the returned CSR and certify it under `pota`
/// (a POTA root → PTA-intermediate chain).
fn issue_pta_chain(
    ctx: &TestCtx,
    session: &SessionHandshake,
    pota: &CaKey,
    seed: &[u8],
    policy: &[u8],
    thumb: &[u8],
) -> PtaChain {
    let init = ctx
        .part_init(session, seed, policy, thumb)
        .expect("PartInit roundtrip");
    make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr))
}

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
