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
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_interface::DdiResult;
use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborPartFinalResp;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborPartInfoResp;
use azihsm_ddi_tbor_types::TborPartInitResp;
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

type HwDevInner = TestCtx;

const CU: u8 = 1;
const ROTATED_CU_PSK: [u8; PSK_LEN] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
];

fn hw_test_reset(test: impl FnOnce(&HwDevInner)) {
    let dev = TestCtx::new();
    test(&dev);
}

fn open_session(
    dev: &HwDevInner,
    psk_id: u8,
    session_type: SessionType,
) -> DdiResult<SessionHandshake> {
    dev.open_session_raw(psk_id, session_type)
}

fn part_init(
    dev: &HwDevInner,
    session: &SessionHandshake,
    seed: &[u8],
    policy: &[u8],
    pota_thumbprint: &[u8],
    sata_thumbprint: &[u8],
    sapota_thumbprint: Option<&[u8]>,
) -> DdiResult<TborPartInitResp> {
    dev.part_init_sd(
        session,
        seed,
        policy,
        pota_thumbprint,
        sata_thumbprint,
        sapota_thumbprint,
    )
}

fn part_final(
    dev: &HwDevInner,
    session: &SessionHandshake,
    policy: &[u8],
    previous_backup: &[u8],
    certs: &[&[u8]],
) -> DdiResult<TborPartFinalResp> {
    dev.part_final(session, policy, previous_backup, certs)
}

fn psk_change(dev: &HwDevInner, session: &SessionHandshake, new_psk: &[u8]) -> DdiResult<()> {
    dev.psk_change(session, new_psk)
}

fn session_close(dev: &HwDevInner, session_id: u16) -> DdiResult<()> {
    dev.session_close(session_id)
}

fn session_open_init_with_options(
    dev: &HwDevInner,
    options: SessionOpenInitOptions<'_>,
) -> DdiResult<crate::harness::session::PendingHandshake> {
    dev.session_open_init_with_options(options)
}

fn session_open_finish(
    dev: &HwDevInner,
    pending: crate::harness::session::PendingHandshake,
) -> DdiResult<SessionHandshake> {
    dev.session_open_finish(pending)
}

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

fn read_part_info(dev: &HwDevInner) -> TborPartInfoResp {
    dev.tbor(&TborPartInfoReq::new())
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

fn assert_device_logical_rejection(err: &DdiError) {
    let code = match err {
        DdiError::TborStatus(status) => status.0,
        DdiError::DdiError(code) => *code,
        other => panic!("expected a firmware logical rejection, got {other:?}"),
    };
    let non_semantic_failures = [
        TborStatus::InternalError.0,
        TborStatus::UnsupportedCmd.0,
        TborStatus::DdiEncodeFailed.0,
        TborStatus::DdiDecodeFailed.0,
    ];
    assert!(
        !non_semantic_failures.contains(&code),
        "firmware returned a non-semantic infrastructure failure: 0x{code:08X}",
    );
}

fn run_part_init(
    dev: &HwDevInner,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    seed: &[u8; MACH_SEED_LEN],
) -> [u8; SEC1_PUB_LEN] {
    let resp = part_init(
        dev,
        session,
        seed,
        &fixture.policy,
        &fixture.thumbprint,
        &sata_thumbprint(),
        None,
    )
    .expect("PartInit roundtrip on hardware");
    pta_pub_from_csr(&resp.pta_csr)
}

fn finalize(
    dev: &HwDevInner,
    session: &SessionHandshake,
    fixture: &PotaFixture,
    previous_backup: &[u8],
    chain: &PtaChain,
) -> Vec<u8> {
    let resp = part_final(
        dev,
        session,
        &fixture.policy,
        previous_backup,
        &chain.der_items(),
    )
    .expect("PartFinal roundtrip on hardware");
    assert_eq!(
        resp.local_mk_backup.len(),
        LOCAL_MK_BACKUP_LEN,
        "PartFinal backup must have the wire-pinned envelope length",
    );
    resp.local_mk_backup
}

fn open_rotated_cu(dev: &HwDevInner) -> SessionHandshake {
    let bootstrap = open_session(dev, CU, SessionType::PlainText).expect("open CU default");
    psk_change(dev, &bootstrap, &ROTATED_CU_PSK).expect("rotate CU PSK");
    session_close(dev, bootstrap.session_id).expect("close bootstrap CU");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = session_open_init_with_options(dev, opts).expect("CU init under rotated PSK");
    session_open_finish(dev, pending).expect("CU finish under rotated PSK")
}

#[test]
fn part_final_full_flow_valid_chain() {
    hw_test_reset(|dev| {
        let before = read_part_info(dev);
        assert_part_state(&before, PART_STATE_ENABLED, "before PartInit");

        let fixture = PotaFixture::generate();
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(dev, &session, &fixture, &mach_seed());
        let chain = fixture.chain_for(&pta_pub);

        let after_init = read_part_info(dev);
        assert_part_state(&after_init, PART_STATE_INITIALIZING, "after PartInit");
        assert_identity_stable(&before, &after_init, "PartInit transition");

        finalize(dev, &session, &fixture, &[], &chain);

        let after_final = read_part_info(dev);
        assert_part_state(&after_final, PART_STATE_INITIALIZED, "after PartFinal");
        assert_identity_stable(&before, &after_final, "PartFinal transition");

        session_close(dev, session.session_id).expect("close finalized CO session");
        let reopened = open_co_with(dev, &ROTATED_CO_PSK);
        let after_reopen = read_part_info(dev);
        assert_part_state(
            &after_reopen,
            PART_STATE_INITIALIZED,
            "after reopening CO session",
        );
        assert_identity_stable(&before, &after_reopen, "session reopen");
        session_close(dev, reopened.session_id).expect("close reopened CO session");
    });
}

#[test]
fn part_final_accepts_prior_backup_across_reset() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let seed = mach_seed();

        let first_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let first_pta_pub = run_part_init(dev, &first_session, &fixture, &seed);
        let chain = fixture.chain_for(&first_pta_pub);
        let first_lineage = read_part_info(dev);
        let backup = finalize(dev, &first_session, &fixture, &[], &chain);
        session_close(dev, first_session.session_id).expect("close first CO session");

        dev.erase().expect("NSSR before prior-backup replay");

        let second_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let second_pta_pub = run_part_init(dev, &second_session, &fixture, &seed);
        assert_eq!(
            second_pta_pub, first_pta_pub,
            "same provisioning inputs must regenerate the same PTA public key",
        );

        let before_restore = read_part_info(dev);
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
        finalize(dev, &second_session, &fixture, &backup, &chain);
        let after_restore = read_part_info(dev);
        assert_part_state(
            &after_restore,
            PART_STATE_INITIALIZED,
            "after prior-backup replay",
        );
        assert_identity_stable(&before_restore, &after_restore, "prior-backup acceptance");
        session_close(dev, second_session.session_id).expect("close restored CO session");
    });
}

#[test]
fn part_final_rejects_tampered_backup_and_allows_retry() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let seed = mach_seed();

        let first_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let first_pta_pub = run_part_init(dev, &first_session, &fixture, &seed);
        let chain = fixture.chain_for(&first_pta_pub);
        let first_lineage = read_part_info(dev);
        let backup = finalize(dev, &first_session, &fixture, &[], &chain);
        session_close(dev, first_session.session_id).expect("close first CO session");

        dev.erase().expect("NSSR before tampered-backup replay");

        let second_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let second_pta_pub = run_part_init(dev, &second_session, &fixture, &seed);
        assert_eq!(
            second_pta_pub, first_pta_pub,
            "same provisioning inputs must regenerate the same PTA public key",
        );

        let before_reject = read_part_info(dev);
        assert_svn_lineage_stable(
            &first_lineage,
            &before_reject,
            "same-lineage tampered-backup replay",
        );
        let mut tampered = backup.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err = part_final(
            dev,
            &second_session,
            &fixture.policy,
            &tampered,
            &chain.der_items(),
        )
        .expect_err("tampered prior backup must be rejected");
        assert_device_logical_rejection(&err);

        let after_reject = read_part_info(dev);
        assert_part_state(
            &after_reject,
            PART_STATE_INITIALIZING,
            "after tampered-backup rejection",
        );
        assert_identity_stable(&before_reject, &after_reject, "tampered-backup rejection");

        finalize(dev, &second_session, &fixture, &backup, &chain);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after retry with untouched backup",
        );
        session_close(dev, second_session.session_id).expect("close restored CO session");
    });
}

#[test]
fn part_final_rejects_policy_mismatch_and_allows_retry() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(dev, &session, &fixture, &mach_seed());
        let chain = fixture.chain_for(&pta_pub);
        let before_reject = read_part_info(dev);

        let mut wrong_policy = fixture.policy;
        wrong_policy[PART_POLICY_LEN - 2] ^= 0x01;
        let err = part_final(dev, &session, &wrong_policy, &[], &chain.der_items())
            .expect_err("policy mismatch must be rejected");
        assert_device_logical_rejection(&err);

        let after_reject = read_part_info(dev);
        assert_part_state(
            &after_reject,
            PART_STATE_INITIALIZING,
            "after policy-mismatch rejection",
        );
        assert_identity_stable(&before_reject, &after_reject, "policy-mismatch rejection");

        finalize(dev, &session, &fixture, &[], &chain);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after retry with original policy",
        );
        session_close(dev, session.session_id).expect("close finalized CO session");
    });
}

/// A PTA chain that is not anchored to the policy `POTAPubKey` must be
/// rejected. M1.0 hardware uses the surrogate-chain implementation, so this
/// full chain-integrity assertion remains emulator-only until M1.5.
#[cfg(feature = "emu")]
#[test]
fn part_final_rejects_unanchored_chain() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(dev, &session, &fixture, &mach_seed());

        let rogue = CaKey::generate();
        let chain = make_pta_chain(&rogue, &pta_pub);
        let err = part_final(dev, &session, &fixture.policy, &[], &chain.der_items())
            .expect_err("a chain not anchored to the policy POTA must be rejected");
        assert_device_logical_rejection(&err);
    });
}

/// A POTA-anchored chain whose terminal certificate carries a key other than
/// the partition PTA key must be rejected. M1.0 hardware uses the
/// surrogate-chain implementation, so this assertion remains emulator-only
/// until M1.5.
#[cfg(feature = "emu")]
#[test]
fn part_final_rejects_pta_mismatch() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        run_part_init(dev, &session, &fixture, &mach_seed());

        let wrong_pta = CaKey::generate();
        let chain = fixture.chain_for(&wrong_pta.sec1_pub());
        let err = part_final(dev, &session, &fixture.policy, &[], &chain.der_items())
            .expect_err("a PTA cert carrying a non-partition key must be rejected");
        assert_device_logical_rejection(&err);
    });
}

#[test]
fn part_final_rejects_backup_from_different_mach_seed() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let seed_a = mach_seed();

        let first_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let first_pta_pub = run_part_init(dev, &first_session, &fixture, &seed_a);
        let chain_a = fixture.chain_for(&first_pta_pub);
        let first_lineage = read_part_info(dev);
        let backup = finalize(dev, &first_session, &fixture, &[], &chain_a);
        session_close(dev, first_session.session_id).expect("close first CO session");

        dev.erase().expect("NSSR before different-seed replay");

        let mut seed_b = seed_a;
        seed_b[0] ^= 0x01;
        let second_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let second_pta_pub = run_part_init(dev, &second_session, &fixture, &seed_b);
        assert_ne!(
            second_pta_pub, first_pta_pub,
            "changing the machine seed must change the derived PTA public key",
        );
        let chain_b = fixture.chain_for(&second_pta_pub);
        let before_reject = read_part_info(dev);
        assert_svn_lineage_stable(
            &first_lineage,
            &before_reject,
            "different-machine-seed replay",
        );

        let err = part_final(
            dev,
            &second_session,
            &fixture.policy,
            &backup,
            &chain_b.der_items(),
        )
        .expect_err("backup from another machine-seed identity must be rejected");
        assert_device_logical_rejection(&err);

        let after_reject = read_part_info(dev);
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

        finalize(dev, &second_session, &fixture, &[], &chain_b);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after fresh finalization for the new identity",
        );
        session_close(dev, second_session.session_id).expect("close finalized CO session");
    });
}

#[test]
fn part_final_rejects_before_part_init() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let before = read_part_info(dev);
        assert_part_state(&before, PART_STATE_ENABLED, "before premature PartFinal");

        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let unrelated_pta = CaKey::generate().sec1_pub();
        let placeholder_chain = fixture.chain_for(&unrelated_pta);
        let err = part_final(
            dev,
            &session,
            &fixture.policy,
            &[],
            &placeholder_chain.der_items(),
        )
        .expect_err("PartFinal before PartInit must be rejected");
        assert_device_logical_rejection(&err);

        let after_reject = read_part_info(dev);
        assert_part_state(
            &after_reject,
            PART_STATE_ENABLED,
            "after premature PartFinal rejection",
        );
        assert_identity_stable(&before, &after_reject, "premature PartFinal rejection");

        let pta_pub = run_part_init(dev, &session, &fixture, &mach_seed());
        let chain = fixture.chain_for(&pta_pub);
        finalize(dev, &session, &fixture, &[], &chain);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after valid PartInit and PartFinal retry",
        );
        session_close(dev, session.session_id).expect("close finalized CO session");
    });
}

#[test]
fn part_final_rejects_cu_and_allows_co_retry() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let co_session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(dev, &co_session, &fixture, &mach_seed());
        let chain = fixture.chain_for(&pta_pub);
        let before_reject = read_part_info(dev);
        session_close(dev, co_session.session_id).expect("close PartInit CO session");

        let cu_session = open_rotated_cu(dev);
        let err = part_final(dev, &cu_session, &fixture.policy, &[], &chain.der_items())
            .expect_err("CU PartFinal must be rejected");
        assert_fw_rejects(&err, TborStatus::InvalidPermissions);
        session_close(dev, cu_session.session_id).expect("close rejected CU session");

        let after_reject = read_part_info(dev);
        assert_part_state(&after_reject, PART_STATE_INITIALIZING, "after CU rejection");
        assert_identity_stable(&before_reject, &after_reject, "CU rejection");

        let retry_session = open_co_with(dev, &ROTATED_CO_PSK);
        finalize(dev, &retry_session, &fixture, &[], &chain);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after CO retry",
        );
        session_close(dev, retry_session.session_id).expect("close retry CO session");
    });
}

#[test]
fn part_final_rejects_second_finalize() {
    hw_test_reset(|dev| {
        let fixture = PotaFixture::generate();
        let session = bootstrap_rotated_co(dev, &ROTATED_CO_PSK);
        let pta_pub = run_part_init(dev, &session, &fixture, &mach_seed());
        let chain = fixture.chain_for(&pta_pub);
        finalize(dev, &session, &fixture, &[], &chain);
        let before_reject = read_part_info(dev);

        let err = part_final(dev, &session, &fixture.policy, &[], &chain.der_items())
            .expect_err("a second PartFinal must be rejected");
        assert_device_logical_rejection(&err);
        let after_reject = read_part_info(dev);
        assert_part_state(
            &after_reject,
            PART_STATE_INITIALIZED,
            "after second PartFinal rejection",
        );
        assert_identity_stable(&before_reject, &after_reject, "second PartFinal rejection");

        session_close(dev, session.session_id).expect("close finalized CO session");
        let reopened = open_co_with(dev, &ROTATED_CO_PSK);
        assert_part_state(
            &read_part_info(dev),
            PART_STATE_INITIALIZED,
            "after reopening CO following second-finalize rejection",
        );
        session_close(dev, reopened.session_id).expect("close reopened CO session");
    });
}
