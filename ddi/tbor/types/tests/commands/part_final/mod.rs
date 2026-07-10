// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end `PartFinal` tests against the std-PAL emulator.
//!
//! `PartFinal` runs after `PartInit` and finalizes the partition: it
//! validates the supplied PTA certificate chain (POTA-anchored, terminal
//! cert == partition PTA key), derives the partition-local masking keys,
//! and returns the current `local_mk` backup.  These tests drive the full
//! `OpenSession → PskChange → PartInit → PartFinal` flow, generating a
//! real POTA-anchored PTA chain on the host (see
//! [`crate::harness::x509_fixture`]) and feeding its certificates out of
//! band so the firmware `x509-chain` validator runs for real.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::PtaChain;
use crate::harness::SessionHandshake;
use crate::harness::TestCtx;

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

/// Happy path: `PartInit` then a first-instantiation `PartFinal`
/// (no prior backup) with a valid POTA-anchored PTA chain returns a
/// `local_mk_backup` of the pinned length.
#[test]
fn part_final_smoke_roundtrip_emu() {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    // The partition owner's POTA trust anchor: its public key is bound
    // into the policy so the chain can be validated against it.
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let chain = issue_pta_chain(
        &ctx,
        &session,
        &pota,
        &mach_seed(),
        &policy,
        &pota_thumbprint(),
    );

    let resp = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal roundtrip");

    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "local_mk_backup must be the masked-envelope length",
    );
}

/// Restore path: a `local_mk_backup` minted on one (fresh) device is
/// accepted on a second device that re-initializes with the same machine
/// seed/owner.  The PTA key is derived deterministically from the seed +
/// policy, so the same chain re-validates on the second device.
#[test]
fn part_final_restore_prev_backup_emu() {
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the device (drops the
    // process-global test lock so a second device can be opened).
    let (backup, chain) = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        let chain = issue_pta_chain(&ctx1, &session1, &pota, &seed, &policy, &thumb);
        let backup = ctx1
            .part_final(&session1, &policy, &[], &chain.der_items())
            .expect("PartFinal roundtrip")
            .local_mk_backup;
        (backup, chain)
    };
    assert_eq!(backup.len(), LOCAL_MK_BACKUP_LEN);

    // Second device, same seed/owner: restore from the prior backup.
    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    let resp = ctx2
        .part_final(&session2, &policy, &backup, &chain.der_items())
        .expect("PartFinal must restore PartLocalMK from a valid prior backup");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "restored backup must be re-masked to the envelope length",
    );
}

/// A tampered `prev_local_mk_backup` must be rejected: flipping a byte in
/// the tag-bound metadata makes the re-derived `PartLocalBMK` unmask fail
/// the AEAD tag check, so restore must error rather than mint blindly.
#[test]
fn part_final_reject_tampered_backup_emu() {
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let seed = mach_seed();
    let thumb = pota_thumbprint();

    // First device: mint a backup, then release the test lock.
    let (mut backup, chain) = {
        let ctx1 = TestCtx::new();
        let session1 = bootstrap_rotated_co(&ctx1, &ROTATED_CO_PSK);
        let chain = issue_pta_chain(&ctx1, &session1, &pota, &seed, &policy, &thumb);
        let backup = ctx1
            .part_final(&session1, &policy, &[], &chain.der_items())
            .expect("PartFinal roundtrip")
            .local_mk_backup;
        (backup, chain)
    };

    // Corrupt the ciphertext/tag region; AEAD verification must fail.
    let last = backup.len() - 1;
    backup[last] ^= 0x01;

    let ctx2 = TestCtx::new();
    let session2 = bootstrap_rotated_co(&ctx2, &ROTATED_CO_PSK);
    ctx2.part_init(&session2, &seed, &policy, &thumb)
        .expect("PartInit roundtrip");
    ctx2.part_final(&session2, &policy, &backup, &chain.der_items())
        .expect_err("PartFinal with a tampered backup must fail the AEAD tag check");
}

/// `PartFinal` before `PartInit` must be rejected: the partition is not
/// in the `Initializing` lifecycle state.  This gate fires before the
/// cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_wrong_state_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let policy = known_good_part_policy();

    ctx.part_final(&session, &policy, &[], &[])
        .expect_err("PartFinal without PartInit must be rejected by the state gate");
}

/// `PartFinal` re-supplying a policy that does not match the one bound at
/// `PartInit` must be rejected (`SHA-384(part_policy) != policy_hash`).
/// This gate fires before the cert-chain walk, so no chain is supplied.
#[test]
fn part_final_reject_policy_mismatch_emu() {
    let ctx = TestCtx::new();

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());

    ctx.part_init(&session, &mach_seed(), &policy, &pota_thumbprint())
        .expect("PartInit roundtrip");

    // Flip a byte in the `info` tail (still a structurally valid policy,
    // but a different SHA-384 digest).
    let mut wrong = policy;
    let last = wrong.len() - 2;
    wrong[last] ^= 0x01;

    ctx.part_final(&session, &wrong, &[], &[])
        .expect_err("PartFinal with a mismatched policy must be rejected");
}

/// A PTA chain that is not anchored to the policy `POTAPubKey` must be
/// rejected: here the chain is rooted at a different CA than the policy's
/// POTA key, so the anchor requirement is never met.
#[test]
fn part_final_reject_unanchored_chain_emu() {
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

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a chain not anchored to the policy POTA must be rejected");
}

/// A POTA-anchored chain whose terminal (PTA) certificate carries a key
/// other than the partition PTA key must be rejected
/// (`PartFinalPtaMismatch`).
#[test]
fn part_final_reject_pta_mismatch_emu() {
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

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA cert carrying a non-partition key must be rejected");
}

/// Regression: after `PartFinal` the partition is `Initialized`, and an
/// `Initialized` partition must continue to serve host IO (the dispatch
/// enable gate includes `Initialized`).  Before that fix any
/// post-finalize command — here `PartInfo` — was silently dropped as a
/// "disabled partition".
#[test]
fn part_final_partition_serves_io_when_initialized_emu() {
    use azihsm_ddi_tbor_types::TborPartInfoReq;

    /// `PartState::Initialized` wire discriminant.
    const PART_STATE_INITIALIZED: u8 = 5;

    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pota = CaKey::generate();
    let policy = part_policy_with_pota(&pota.raw_pub());
    let chain = issue_pta_chain(
        &ctx,
        &session,
        &pota,
        &mach_seed(),
        &policy,
        &pota_thumbprint(),
    );

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    // The partition is now Initialized; a follow-up command must still be
    // served rather than dropped as a disabled partition.
    let info = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after PartFinal must be served");
    assert_eq!(
        info.part_state, PART_STATE_INITIALIZED,
        "PartInfo must report Initialized after PartFinal",
    );
}
