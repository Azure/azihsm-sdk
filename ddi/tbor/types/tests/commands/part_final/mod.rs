// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the TBOR `PartFinal` command.
//!
//! The shared tests exercise `OpenSession -> PskChange -> PartInit ->
//! PartFinal` on both the emulator and native hardware backends. Every shared
//! case builds a syntactically valid POTA-to-PTA certificate chain. Emulator
//! runs transfer and validate that chain; native M1.0 runs send the
//! schema-required placeholder descriptor because the current firmware
//! intentionally does not consume certificate OOB data. The two tests that
//! specifically validate certificate-chain integrity remain emulator-only
//! until M1.5.
//!
//! The prior-backup acceptance case is intentionally a smoke test. M1.0 has no
//! public command that consumes a Local-scope masked artifact, so accepting the
//! backup cannot by itself prove that the original `PartLocalMK` plaintext was
//! restored. That stronger continuity test must be added when such an API is
//! available.

use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborPartInfoResp;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::LOCAL_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::MACH_SEED_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POTA_THUMBPRINT_LEN;
use azihsm_ddi_tbor_types::PSK_LEN;

use crate::commands::part_init::bootstrap_rotated_co;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::open_co_with;
use crate::commands::part_init::part_policy_with_pota;
use crate::commands::part_init::sata_thumbprint;
use crate::commands::part_init::ROTATED_CO_PSK;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::x509_fixture::build_pta_intermediate;
use crate::harness::x509_fixture::build_root;
#[cfg(feature = "emu")]
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::PtaChain;
use crate::harness::x509_fixture::SEC1_PUB_LEN;
use crate::harness::SessionHandshake;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;

const CU: u8 = 1;
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

#[cfg(feature = "emu")]
const BACKUP_AUTH_FAILURE: TborStatus = TborStatus::AesGcmDecryptTagDoesNotMatch;
#[cfg(not(feature = "emu"))]
const BACKUP_AUTH_FAILURE: TborStatus = TborStatus::AeadEnvelopeAuthFailed;

const PART_STATE_ENABLED: u8 = 2;
const PART_STATE_INITIALIZING: u8 = 4;
const PART_STATE_INITIALIZED: u8 = 5;

struct PotaFixture {
    ca: CaKey,
    root_der: Vec<u8>,
    policy: [u8; PART_POLICY_LEN],
    thumbprint: [u8; POTA_THUMBPRINT_LEN],
}

impl PotaFixture {
    fn generate() -> Self {
        let ca = CaKey::generate();
        let root_der = build_root(&ca);
        let policy = part_policy_with_pota(&ca.raw_pub());
        let thumbprint = sha384(&root_der);
        Self {
            ca,
            root_der,
            policy,
            thumbprint,
        }
    }

    fn chain_for(&self, pta_pub: &[u8; SEC1_PUB_LEN]) -> PtaChain {
        PtaChain {
            root_der: self.root_der.clone(),
            pta_der: build_pta_intermediate(pta_pub, &self.ca),
        }
    }
}

fn sha384(input: &[u8]) -> [u8; POTA_THUMBPRINT_LEN] {
    let mut hash = HashAlgo::sha384();
    let mut out = [0u8; POTA_THUMBPRINT_LEN];
    hash.hash(input, Some(&mut out)).expect("SHA-384");
    out
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
    let resp = ctx
        .part_init_sd(
            session,
            seed,
            &fixture.policy,
            &fixture.thumbprint,
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
    let resp = ctx
        .part_final(
            session,
            &fixture.policy,
            previous_backup,
            &chain.der_items(),
        )
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

#[test]
fn part_final_smoke_roundtrip() {
    let ctx = TestCtx::new();
    let before = read_part_info(&ctx);
    assert_part_state(&before, PART_STATE_ENABLED, "before PartInit");

    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);

    let after_init = read_part_info(&ctx);
    assert_part_state(&after_init, PART_STATE_INITIALIZING, "after PartInit");
    assert_identity_stable(&before, &after_init, "PartInit transition");

    finalize(&ctx, &session, &fixture, &[], &chain);

    let after_final = read_part_info(&ctx);
    assert_part_state(&after_final, PART_STATE_INITIALIZED, "after PartFinal");
    assert_identity_stable(&before, &after_final, "PartFinal transition");

    ctx.session_close(session.session_id)
        .expect("close finalized CO session");
    let reopened = open_co_with(&ctx, &ROTATED_CO_PSK);
    let after_reopen = read_part_info(&ctx);
    assert_part_state(
        &after_reopen,
        PART_STATE_INITIALIZED,
        "after reopening CO session",
    );
    assert_identity_stable(&before, &after_reopen, "session reopen");
    ctx.session_close(reopened.session_id)
        .expect("close reopened CO session");
}

#[test]
fn part_final_accepts_prior_backup_across_reset() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let first_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let first_pta_pub = run_part_init(&ctx, &first_session, &fixture, &seed);
    let chain = fixture.chain_for(&first_pta_pub);
    let first_lineage = read_part_info(&ctx);
    let backup = finalize(&ctx, &first_session, &fixture, &[], &chain);
    ctx.session_close(first_session.session_id)
        .expect("close first CO session");

    ctx.erase().expect("NSSR before prior-backup replay");

    let second_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let second_pta_pub = run_part_init(&ctx, &second_session, &fixture, &seed);
    assert_eq!(
        second_pta_pub, first_pta_pub,
        "same provisioning inputs must regenerate the same PTA public key",
    );

    let before_restore = read_part_info(&ctx);
    assert_svn_lineage_stable(
        &first_lineage,
        &before_restore,
        "same-lineage prior-backup replay",
    );
    assert_part_state(
        &before_restore,
        PART_STATE_INITIALIZING,
        "before prior-backup replay",
    );
    finalize(&ctx, &second_session, &fixture, &backup, &chain);
    let after_restore = read_part_info(&ctx);
    assert_part_state(
        &after_restore,
        PART_STATE_INITIALIZED,
        "after prior-backup replay",
    );
    assert_identity_stable(&before_restore, &after_restore, "prior-backup acceptance");
    ctx.session_close(second_session.session_id)
        .expect("close restored CO session");
}

#[test]
fn part_final_rejects_tampered_backup_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let seed = mach_seed();

    let first_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let first_pta_pub = run_part_init(&ctx, &first_session, &fixture, &seed);
    let chain = fixture.chain_for(&first_pta_pub);
    let first_lineage = read_part_info(&ctx);
    let backup = finalize(&ctx, &first_session, &fixture, &[], &chain);
    ctx.session_close(first_session.session_id)
        .expect("close first CO session");

    ctx.erase().expect("NSSR before tampered-backup replay");

    let second_session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let second_pta_pub = run_part_init(&ctx, &second_session, &fixture, &seed);
    assert_eq!(
        second_pta_pub, first_pta_pub,
        "same provisioning inputs must regenerate the same PTA public key",
    );

    let before_reject = read_part_info(&ctx);
    assert_svn_lineage_stable(
        &first_lineage,
        &before_reject,
        "same-lineage tampered-backup replay",
    );
    let mut tampered = backup.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let err = ctx
        .part_final(
            &second_session,
            &fixture.policy,
            &tampered,
            &chain.der_items(),
        )
        .expect_err("tampered prior backup must be rejected");
    assert_fw_rejects(&err, BACKUP_AUTH_FAILURE);

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after tampered-backup rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "tampered-backup rejection");

    finalize(&ctx, &second_session, &fixture, &backup, &chain);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after retry with untouched backup",
    );
    ctx.session_close(second_session.session_id)
        .expect("close restored CO session");
}

#[test]
fn part_final_rejects_policy_mismatch_and_allows_retry() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    let before_reject = read_part_info(&ctx);

    let mut wrong_policy = fixture.policy;
    wrong_policy[PART_POLICY_LEN - 2] ^= 0x01;
    let err = ctx
        .part_final(&session, &wrong_policy, &[], &chain.der_items())
        .expect_err("policy mismatch must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_INITIALIZING,
        "after policy-mismatch rejection",
    );
    assert_identity_stable(&before_reject, &after_reject, "policy-mismatch rejection");

    finalize(&ctx, &session, &fixture, &[], &chain);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after retry with original policy",
    );
    ctx.session_close(session.session_id)
        .expect("close finalized CO session");
}

/// A PTA chain that is not anchored to the policy `POTAPubKey` must be
/// rejected. M1.0 hardware uses the surrogate-chain implementation, so this
/// full chain-integrity assertion remains emulator-only until M1.5.
#[cfg(feature = "emu")]
#[test]
fn part_final_rejects_unanchored_chain() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());

    let rogue = CaKey::generate();
    let chain = make_pta_chain(&rogue, &pta_pub);
    let err = ctx
        .part_final(&session, &fixture.policy, &[], &chain.der_items())
        .expect_err("a chain not anchored to the policy POTA must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);
}

/// A POTA-anchored chain whose terminal certificate carries a key other than
/// the partition PTA key must be rejected. M1.0 hardware uses the
/// surrogate-chain implementation, so this assertion remains emulator-only
/// until M1.5.
#[cfg(feature = "emu")]
#[test]
fn part_final_rejects_pta_mismatch() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    run_part_init(&ctx, &session, &fixture, &mach_seed());

    let wrong_pta = CaKey::generate();
    let chain = fixture.chain_for(&wrong_pta.sec1_pub());
    let err = ctx
        .part_final(&session, &fixture.policy, &[], &chain.der_items())
        .expect_err("a PTA cert carrying a non-partition key must be rejected");
    assert_fw_rejects(&err, TborStatus::PartFinalPtaMismatch);
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
            &fixture.policy,
            &backup,
            &chain_b.der_items(),
        )
        .expect_err("backup from another machine-seed identity must be rejected");
    assert_fw_rejects(&err, BACKUP_AUTH_FAILURE);

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
fn part_final_rejects_before_part_init() {
    let ctx = TestCtx::new();
    let fixture = PotaFixture::generate();
    let before = read_part_info(&ctx);
    assert_part_state(&before, PART_STATE_ENABLED, "before premature PartFinal");

    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let unrelated_pta = CaKey::generate().sec1_pub();
    let placeholder_chain = fixture.chain_for(&unrelated_pta);
    let err = ctx
        .part_final(
            &session,
            &fixture.policy,
            &[],
            &placeholder_chain.der_items(),
        )
        .expect_err("PartFinal before PartInit must be rejected");
    assert_fw_rejects(&err, TborStatus::InvalidArg);

    let after_reject = read_part_info(&ctx);
    assert_part_state(
        &after_reject,
        PART_STATE_ENABLED,
        "after premature PartFinal rejection",
    );
    assert_identity_stable(&before, &after_reject, "premature PartFinal rejection");

    let pta_pub = run_part_init(&ctx, &session, &fixture, &mach_seed());
    let chain = fixture.chain_for(&pta_pub);
    finalize(&ctx, &session, &fixture, &[], &chain);
    assert_part_state(
        &read_part_info(&ctx),
        PART_STATE_INITIALIZED,
        "after valid PartInit and PartFinal retry",
    );
    ctx.session_close(session.session_id)
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
        .part_final(&cu_session, &fixture.policy, &[], &chain.der_items())
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
        .part_final(&session, &fixture.policy, &[], &chain.der_items())
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
