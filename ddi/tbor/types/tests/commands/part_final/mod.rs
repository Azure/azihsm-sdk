// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the TBOR `PartFinal` command.
//!
//! The original emulator test bodies are preserved and run on native hardware
//! where M1.0 behavior supports the same contract. Additional tests cover
//! lifecycle, identity, retry, and exact-status behavior without changing the
//! original cases. Emulator runs transfer and validate each POTA-to-PTA chain;
//! native M1.0 runs send the schema-required placeholder descriptor because the
//! current firmware intentionally does not consume certificate OOB data.
//! Tests that specifically validate certificate-chain integrity remain
//! emulator-only until M1.5.
//!
//! The prior-backup acceptance case is intentionally a smoke test. M1.0 has no
//! public command that consumes a Local-scope masked artifact, so accepting the
//! backup cannot by itself prove that the original `PartLocalMK` plaintext was
//! restored. That stronger continuity test must be added when such an API is
//! available.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborPartInfoResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::known_good_part_policy;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::open_co_with;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::part_init::sata_thumbprint;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::PotaFixture;
use crate::harness::x509_fixture::PtaChain;
use crate::harness::x509_fixture::SEC1_PUB_LEN;
use crate::harness::SessionHandshake;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::CU_PSK_ID as CU;
use crate::harness::ROTATED_CU_PSK;

const PART_STATE_INITIALIZING: u8 = 4;
const PART_STATE_INITIALIZED: u8 = 5;

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

fn pota_policy(fixture: &PotaFixture) -> [u8; PART_POLICY_LEN] {
    part_policy_with_pota(&fixture.raw_pub())
}

fn read_part_info(ctx: &TestCtx) -> TborPartInfoResp {
    ctx.tbor(&TborPartInfoReq::new())
        .expect("PartInfo roundtrip")
}

fn assert_part_state(info: &TborPartInfoResp, expected: u8, context: &str) {
    assert_eq!(
        info.part_state, expected,
        "{context}: unexpected partition lifecycle state",
    );
}

fn assert_identity_stable(before: &TborPartInfoResp, after: &TborPartInfoResp, context: &str) {
    assert_eq!(after.pid, before.pid, "{context}: PID changed");
    assert_eq!(
        after.pid_pub_key, before.pid_pub_key,
        "{context}: PID public key changed",
    );
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "{context}: owner SVN changed",
    );
    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "{context}: manufacturer SVN changed",
    );
}

fn assert_svn_lineage_stable(before: &TborPartInfoResp, after: &TborPartInfoResp, context: &str) {
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "{context}: owner SVN lineage changed",
    );
    assert_eq!(
        after.mfgr_svn, before.mfgr_svn,
        "{context}: manufacturer SVN lineage changed",
    );
}

fn run_part_init(
    ctx: &TestCtx,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    seed: &[u8; MACH_SEED_LEN],
) -> [u8; SEC1_PUB_LEN] {
    let policy = pota_policy(fixture);
    let resp = ctx
        .part_init_sd(
            session,
            seed,
            &policy,
            fixture.thumbprint(),
            &sata_thumbprint(),
            None,
        )
        .expect("PartInit roundtrip");
    pta_pub_from_csr(&resp.pta_csr)
}

fn finalize(
    ctx: &TestCtx,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    previous_backup: &[u8],
    chain: &PtaChain,
) -> Vec<u8> {
    let policy = pota_policy(fixture);
    let resp = ctx
        .part_final(session, &policy, previous_backup, &chain.der_items())
        .expect("PartFinal roundtrip");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "PartFinal backup must have the wire-pinned envelope length",
    );
    resp.local_mk_backup
}

fn open_rotated_cu(ctx: &TestCtx) -> SessionHandshake {
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open CU default");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU init under rotated PSK");
    ctx.session_open_finish(pending)
        .expect("CU finish under rotated PSK")
}

/// Happy path: `PartInit` then a first-instantiation `PartFinal`
/// (no prior backup) with a valid POTA-anchored PTA chain returns a
/// `local_mk_backup` of the pinned length.
#[test]
fn part_final_smoke_roundtrip() {
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
fn part_final_restore_prev_backup() {
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
fn part_final_reject_tampered_backup() {
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
fn part_final_reject_wrong_state() {
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
fn part_final_reject_policy_mismatch() {
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
#[cfg(feature = "emu")]
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

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a chain not anchored to the policy POTA must be rejected");
}

/// A POTA-anchored chain whose terminal (PTA) certificate carries a key
/// other than the partition PTA key must be rejected
/// (`PartFinalPtaMismatch`).
#[cfg(feature = "emu")]
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

    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect_err("a PTA cert carrying a non-partition key must be rejected");
}

/// Regression: after `PartFinal` the partition is `Initialized`, and an
/// `Initialized` partition must continue to serve host IO (the dispatch
/// enable gate includes `Initialized`).  Before that fix any
/// post-finalize command — here `PartInfo` — was silently dropped as a
/// "disabled partition".
#[test]
fn part_final_partition_serves_io_when_initialized() {
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

#[test]
fn part_final_rejects_backup_from_different_mach_seed() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed_a = mach_seed();

    let first_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let first_pta_pub = run_part_init(&ctx, &first_session, &fixture, &seed_a);
    let chain_a = fixture.chain_for(&first_pta_pub);
    let first_lineage = read_part_info(&ctx);
    let backup = finalize(&ctx, &first_session, &fixture, &[], &chain_a);
    ctx.session_close(first_session.session_id)
        .expect("close first CO session");

    ctx.erase().expect("NSSR before different-seed replay");

    let mut seed_b = seed_a;
    seed_b[0] ^= 0x01;
    let second_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let second_pta_pub = run_part_init(&ctx, &second_session, &fixture, &seed_b);
    assert_ne!(
        second_pta_pub, first_pta_pub,
        "changing the machine seed must change the derived PTA public key",
    );
    let chain_b = fixture.chain_for(&second_pta_pub);
    let before_reject = read_part_info(&ctx);
    assert_svn_lineage_stable(
        &first_lineage,
        &before_reject,
        "different-machine-seed replay",
    );

    let err = ctx
        .part_final(
            &second_session,
            &pota_policy(&fixture),
            &backup,
            &chain_b.der_items(),
        )
        .expect_err("backup from another machine-seed identity must be rejected");
    assert_fw_rejects(&err, TborStatus::AesGcmDecryptTagDoesNotMatch);

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after cross-identity backup rejection",
    );
    assert_identity_stable(
        &before_reject,
        &after_reject,
        "cross-identity backup rejection",
    );

    finalize(&ctx, &second_session, &fixture, &[], &chain_b);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after fresh finalization for the new identity",
    );
    ctx.session_close(second_session.session_id)
        .expect("close finalized CO session");
}
#[test]
fn part_final_rejects_cu_and_allows_co_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let co_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &co_session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    let before_reject = read_part_info(&ctx);
    ctx.session_close(co_session.session_id)
        .expect("close PartInit CO session");

    let cu_session = open_rotated_cu(&ctx);
    let err = ctx
        .part_final(&cu_session, &pota_policy(&fixture), &[], &chain.der_items())
        .expect_err("CU PartFinal must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidPermissions);
    ctx.session_close(cu_session.session_id)
        .expect("close rejected CU session");

    let after_reject = read_part_info(&ctx);
    assert_part_state(&after_reject, PART_STATE_INITIALIZING, "after CU rejection");
    assert_identity_stable(&before_reject, &after_reject, "CU rejection");

    let retry_session = open_co_with(&ctx, &ROTATED_CO_PSK);
    finalize(&ctx, &retry_session, &fixture, &[], &chain);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after CO retry",
    );
    ctx.session_close(retry_session.session_id)
        .expect("close retry CO session");
}

#[test]
fn part_final_rejects_second_finalize() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    finalize(&ctx, &session, &fixture, &[], &chain);
    let before_reject = read_part_info(&ctx);

    let err = ctx
        .part_final(&session, &pota_policy(&fixture), &[], &chain.der_items())
        .expect_err("a second PartFinal must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZED,
        "after second PartFinal rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "second PartFinal rejection");

    ctx.session_close(session.session_id)
        .expect("close finalized CO session");
    let reopened = open_co_with(&ctx, &ROTATED_CO_PSK);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after reopening CO following second-finalize rejection",
    );
    ctx.session_close(reopened.session_id)
        .expect("close reopened CO session");
}
