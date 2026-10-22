// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdCreatePeerBackup` command.
//!
//! `SdCreatePeerBackup` recovers BKS3 from the caller's device-local
//! backup (`pok_local_backup`) and HPKE-Auth-seals it to a destination
//! peer named by `dst_evidence` — authenticated by the sender's own masked
//! SD-sealing key — returning the peer backup (`pok_peer_backup`, a 161-byte
//! HPKE seal).  It is **stateless** and gated by the security domain's
//! `allow_peer_cloning` policy flag.
//!
//! These tests run a **self-peer** backup (sender == receiver): one
//! partition mints an SD sealing key, attests it via `KeyReport`, creates
//! its security domain, and then re-seals the recovered BKS3 to its own
//! attested public key.
//!
//! Coverage:
//! * Round-trip — non-zero 161-byte `pok_peer_backup`.
//! * Policy without `allow_peer_cloning` → `SdPeerCloningNotAllowed`.
//! * Not finalized → `InvalidArg`.

use azihsm_ddi_tbor_test_harness::bootstrap_rotated_co;
use azihsm_ddi_tbor_test_harness::x509_fixture::make_pta_chain;
use azihsm_ddi_tbor_test_harness::x509_fixture::pta_pub_from_csr;
use azihsm_ddi_tbor_test_harness::x509_fixture::CaKey;
use azihsm_ddi_tbor_test_harness::x509_fixture::RAW_PUB_LEN;
use azihsm_ddi_tbor_test_harness::SessionHandshake;
use azihsm_ddi_tbor_test_harness::TestCtx;
use azihsm_ddi_tbor_test_harness::ROTATED_CO_PSK;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdCreatePeerBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use zerocopy::{IntoBytes, TryFromBytes};

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_report_and_pub;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;

/// Byte offset of the `flags` field in the 484-byte `PartPolicy` image.
const OFF_FLAGS: usize = 418;

/// `PolicyFlags::ALLOW_PEER_CLONING` (bit 2) — mirror of the firmware
/// policy flag that gates the peer-backup commands.
const ALLOW_PEER_CLONING: u8 = 1 << 2;

/// A finalized backing partition ready for the peer-backup commands: the
/// live CO session, its exact policy image, its PID public key (every
/// evidence leaf certifies it), and `PartFinal`'s `local_mk_backup`
/// (replayed on a rebooted peer to restore `PartLocalMK`).
pub(crate) struct PeerPartition {
    pub(crate) session: SessionHandshake,
    pub(crate) policy: [u8; PART_POLICY_LEN],
    pub(crate) pid_pub: [u8; RAW_PUB_LEN],
    pub(crate) local_mk_backup: Vec<u8>,
}

/// Drive `PartInit → PartFinal` on `ctx` with a backing-partition policy
/// anchored to `sata`/`pota`, optionally opting the security domain into
/// peer cloning.  The same policy image must be replayed verbatim by the
/// peer-backup commands (for the `policy_hash` re-check).
pub(crate) fn finalize_peer_partition(
    ctx: &TestCtx,
    seed: &[u8],
    sata: &CaKey,
    pota: &CaKey,
    allow_cloning: bool,
) -> PeerPartition {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);

    let mut policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );
    if allow_cloning {
        policy[OFF_FLAGS] |= ALLOW_PEER_CLONING;
    }

    let init = ctx
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    PeerPartition {
        session,
        policy,
        pid_pub,
        local_mk_backup,
    }
}

/// Assemble a `SdCreatePeerBackup` request from a masked sealing key,
/// destination evidence, policy, and the local backup to re-seal.
pub(crate) fn create_peer_req(
    session_id: u16,
    masked_sealing_key: &[u8],
    evidence: &ReceiverEvidence,
    policy: &[u8; PART_POLICY_LEN],
    pok_local_backup: &[u8; MASKED_SD_LEN],
) -> TborSdCreatePeerBackupReq {
    TborSdCreatePeerBackupReq {
        session_id,
        masked_sealing_key: masked_sealing_key
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(policy).expect("policy image is canonical"),
        dst_mfgr_cert_chain: evidence.mfgr.clone(),
        dst_owner_cert_chain: evidence.owner.clone(),
        dst_part_owner_cert_chain: evidence.part_owner.clone(),
        dst_report: evidence.report,
        pok_local_backup: *pok_local_backup,
    }
}

#[test]
fn sd_create_peer_backup_roundtrip() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, true);
    let session_id = part.session.session_id;

    // Mint + attest a sealing key, then create the security domain to
    // obtain the device-local backup this command re-seals.
    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, &sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");

    let req = create_peer_req(
        session_id,
        &masked,
        &evidence,
        &part.policy,
        &created.pok_local_backup,
    );
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreatePeerBackup roundtrip");

    assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        resp.pok_peer_backup.iter().any(|&b| b != 0),
        "pok_peer_backup must not be all-zero",
    );
}

#[test]
fn sd_create_peer_backup_rejects_without_peer_cloning() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Finalize with a policy that does NOT opt into peer cloning.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, false);
    let session_id = part.session.session_id;

    // A real sealing key + evidence so the request reaches the policy gate;
    // the peer-cloning check fires before any local backup is unmasked, so
    // a zero `pok_local_backup` is sufficient.
    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, &sata, &report);
    let req = create_peer_req(
        session_id,
        &masked,
        &evidence,
        &part.policy,
        &[0u8; MASKED_SD_LEN],
    );
    ctx.expect_fw_reject_oob(&req, &evidence.oob(), TborStatus::SdPeerCloningNotAllowed);
}

#[test]
fn sd_create_peer_backup_rejects_before_finalize() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdCreatePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
        policy: PartPolicy::zeroed(),
        dst_mfgr_cert_chain: Vec::new(),
        dst_owner_cert_chain: Vec::new(),
        dst_part_owner_cert_chain: Vec::new(),
        dst_report: Default::default(),
        pok_local_backup: [0u8; MASKED_SD_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}

/// Build a valid peer-backup request for negative and repeated-call tests.
fn valid_peer_backup_fixture() -> (TestCtx, TborSdCreatePeerBackupReq, ReceiverEvidence) {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, true);
    let session_id = part.session.session_id;

    let (masked, report, rcvr_pub) = masked_key_report_and_pub(&ctx, session_id);

    let evidence = build_receiver_evidence(&part.pid_pub, &rcvr_pub, &sata, &report);

    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup setup");

    let req = create_peer_req(
        session_id,
        &masked,
        &evidence,
        &part.policy,
        &created.pok_local_backup,
    );

    (ctx, req, evidence)
}

/// Reject a peer-backup request using an invalid session ID.
#[test]
fn sd_create_peer_backup_rejects_invalid_session_id() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.session_id = if req.session_id == u16::MAX {
        u16::MAX - 1
    } else {
        u16::MAX
    };

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject an invalid session ID",
    );
}

/// Reject a local SD backup whose contents have been corrupted.
#[test]
fn sd_create_peer_backup_rejects_corrupted_local_backup() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.pok_local_backup[0] ^= 0x01;

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject a corrupted local backup",
    );
}

/// Reject an all-zero local SD backup.
#[test]
fn sd_create_peer_backup_rejects_zero_local_backup() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.pok_local_backup = [0u8; MASKED_SD_LEN];

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject an all-zero local backup",
    );
}

/// Reject a request whose policy disables peer cloning.
#[test]
fn sd_create_peer_backup_rejects_modified_policy() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    let mut policy_bytes = [0u8; PART_POLICY_LEN];
    policy_bytes.copy_from_slice(req.policy.as_bytes());
    policy_bytes[OFF_FLAGS] &= !ALLOW_PEER_CLONING;

    req.policy = PartPolicy::try_read_from_bytes(&policy_bytes).expect("modified policy image");

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject a modified policy",
    );
}

/// Reject a request containing an all-zero masked sealing key.
#[test]
fn sd_create_peer_backup_rejects_zero_masked_sealing_key() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.masked_sealing_key = [0u8; MASKED_SEALING_KEY_LEN];

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject an invalid sealing key",
    );
}

/// Reject missing destination manufacturer certificates.
#[test]
fn sd_create_peer_backup_rejects_empty_mfgr_cert_chain() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.dst_mfgr_cert_chain.clear();

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject missing manufacturer certificates",
    );
}

/// Reject missing destination owner certificates.
#[test]
fn sd_create_peer_backup_rejects_empty_owner_cert_chain() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.dst_owner_cert_chain.clear();

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject missing owner certificates",
    );
}

/// Reject missing destination partition-owner certificates.
#[test]
fn sd_create_peer_backup_rejects_empty_part_owner_cert_chain() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.dst_part_owner_cert_chain.clear();

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject missing partition-owner certificates",
    );
}

/// Reject an invalid destination attestation report.
#[test]
fn sd_create_peer_backup_rejects_invalid_destination_report() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.dst_report = Default::default();

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject invalid destination attestation",
    );
}

/// Allow repeated peer-backup requests without additional state changes.
#[test]
fn sd_create_peer_backup_allows_repeated_calls() {
    let (ctx, req, evidence) = valid_peer_backup_fixture();

    for attempt in 0..3 {
        let resp = ctx
            .tbor_oob(&req, &evidence.oob())
            .expect("repeated SdCreatePeerBackup");

        assert_eq!(
            resp.pok_peer_backup.len(),
            POK_REMOTE_BACKUP_LEN,
            "unexpected backup length on attempt {attempt}",
        );

        assert!(
            resp.pok_peer_backup.iter().any(|&b| b != 0),
            "empty backup on attempt {attempt}",
        );
    }
}

/// Reject corruption near the end of the local SD backup.
#[test]
fn sd_create_peer_backup_rejects_corrupted_local_backup_tail() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.pok_local_backup[MASKED_SD_LEN - 1] ^= 0x01;

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject corrupted backup tail",
    );
}

/// Reject corruption at multiple offsets within the local SD backup.
#[test]
fn sd_create_peer_backup_rejects_local_backup_corruption_at_offsets() {
    let offsets = [0, MASKED_SD_LEN / 4, MASKED_SD_LEN / 2, MASKED_SD_LEN - 1];

    for offset in offsets {
        let (ctx, mut req, evidence) = valid_peer_backup_fixture();

        req.pok_local_backup[offset] ^= 0x01;

        assert!(
            ctx.tbor_oob(&req, &evidence.oob()).is_err(),
            "SdCreatePeerBackup accepted corrupted backup at offset {offset}",
        );
    }
}

/// Reject corruption in the first byte of the masked sealing key.
#[test]
fn sd_create_peer_backup_rejects_corrupted_masked_sealing_key_header() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.masked_sealing_key[0] ^= 0x01;

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject a corrupted masked key header",
    );
}

/// Reject corruption near the end of the masked sealing key.
#[test]
fn sd_create_peer_backup_rejects_corrupted_masked_sealing_key_tail() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.masked_sealing_key[MASKED_SEALING_KEY_LEN - 1] ^= 0x01;

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject a corrupted masked key tail",
    );
}

/// Reject a destination with all certificate chains missing.
#[test]
fn sd_create_peer_backup_rejects_all_empty_cert_chains() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    req.dst_mfgr_cert_chain.clear();
    req.dst_owner_cert_chain.clear();
    req.dst_part_owner_cert_chain.clear();

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject missing certificate chains",
    );
}

/// Preserve a valid session after a rejected peer-backup request.
#[test]
fn sd_create_peer_backup_valid_after_rejected_request() {
    let (ctx, req, evidence) = valid_peer_backup_fixture();

    let mut invalid_req = req.clone();
    invalid_req.pok_local_backup = [0u8; MASKED_SD_LEN];

    assert!(
        ctx.tbor_oob(&invalid_req, &evidence.oob()).is_err(),
        "Invalid peer-backup request must be rejected",
    );

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("Valid peer backup must succeed after rejected request");

    assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);

    assert!(
        resp.pok_peer_backup.iter().any(|&b| b != 0),
        "Valid peer backup must not be all-zero",
    );
}

/// Reject repeated invalid local backups without losing session state.
#[test]
fn sd_create_peer_backup_rejects_repeated_invalid_backups() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    for attempt in 0..3 {
        req.pok_local_backup = [0u8; MASKED_SD_LEN];

        assert!(
            ctx.tbor_oob(&req, &evidence.oob()).is_err(),
            "Invalid backup accepted on attempt {attempt}",
        );
    }
}

/// Preserve the active session after an invalid session ID request.
#[test]
fn sd_create_peer_backup_valid_after_invalid_session_id() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    let valid_session_id = req.session_id;

    req.session_id = if valid_session_id == u16::MAX {
        u16::MAX - 1
    } else {
        u16::MAX
    };

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "Invalid session ID must be rejected",
    );

    req.session_id = valid_session_id;

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("Valid session must remain usable");

    assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);
}

/// Preserve a valid session after several different malformed requests.
#[test]
fn sd_create_peer_backup_recovers_after_multiple_failures() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    let original_backup = req.pok_local_backup;
    let original_key = req.masked_sealing_key;

    req.pok_local_backup = [0u8; MASKED_SD_LEN];

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "Zero local backup must be rejected",
    );

    req.pok_local_backup = original_backup;
    req.masked_sealing_key = [0u8; MASKED_SEALING_KEY_LEN];

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "Zero masked sealing key must be rejected",
    );

    req.masked_sealing_key = original_key;

    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("Valid request must succeed after failures");

    assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);

    assert!(
        resp.pok_peer_backup.iter().any(|&b| b != 0),
        "Valid peer backup must not be all-zero",
    );
}

/// Allow a valid peer-backup request after repeated successful operations.
#[test]
fn sd_create_peer_backup_remains_usable_after_successes() {
    let (ctx, req, evidence) = valid_peer_backup_fixture();

    for attempt in 0..5 {
        let resp = ctx
            .tbor_oob(&req, &evidence.oob())
            .expect("Repeated peer backup must succeed");

        assert_eq!(
            resp.pok_peer_backup.len(),
            POK_REMOTE_BACKUP_LEN,
            "Unexpected backup length on attempt {attempt}",
        );

        assert!(
            resp.pok_peer_backup.iter().any(|&b| b != 0),
            "All-zero backup on attempt {attempt}",
        );
    }
}

/// Reject a peer-backup request using an inactive session ID.
#[test]
fn sd_create_peer_backup_rejects_max_session_id() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    let valid_session_id = req.session_id;

    req.session_id = if valid_session_id == u16::MAX {
        u16::MAX - 1
    } else {
        u16::MAX
    };

    assert!(
        ctx.tbor_oob(&req, &evidence.oob()).is_err(),
        "SdCreatePeerBackup must reject an inactive session ID",
    );
}

/// Verify that session ID zero is rejected only when it is inactive.
#[test]
fn sd_create_peer_backup_zero_session_id_boundary() {
    let (ctx, mut req, evidence) = valid_peer_backup_fixture();

    let active_session_id = req.session_id;

    if active_session_id == 0 {
        let resp = ctx
            .tbor_oob(&req, &evidence.oob())
            .expect("Active session ID zero must be accepted");

        assert_eq!(resp.pok_peer_backup.len(), POK_REMOTE_BACKUP_LEN);
    } else {
        req.session_id = 0;

        assert!(
            ctx.tbor_oob(&req, &evidence.oob()).is_err(),
            "Inactive session ID zero must be rejected",
        );
    }
}
