// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreRemoteBackup` command.
//!
//! `SdRestoreRemoteBackup` restores a security domain from a **remote**
//! backup: it HPKE-Auth-opens `src_remote_backup` (an HPKE seal of BKS3)
//! with the receiver's masked SD-sealing key — authenticated by the
//! sender's attested key — recovers `SDMK` from `prev_sd_mk_backup`, and
//! returns the device-local backups.
//!
//! The **round-trip** test uses a self-backup (sender == receiver): a first
//! device finalizes and `CreateSD`s (producing the `pok_remote_backup` /
//! `sd_mk_backup` this command consumes, plus the `local_mk_backup`), then a
//! second device (factory-reset, same machine seed) restores `PartLocalMK`
//! via `PartFinal` — so it can unmask the captured sealing key — and
//! restores the security domain from the remote backup.
//!
//! Coverage:
//! * Round-trip — create → reboot → PartFinal(restore PartLocalMK) →
//!   restore-remote returns non-zero refreshed local backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Restore before finalize → `InvalidArg`.

use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreRemoteBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::mach_seed;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::PotaFixture;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// A remote backup produced by the first device's `CreateSD`, replayed on
/// the second (rebooted) device to restore the security domain.
struct RemoteBackup {
    /// The receiver's masked SD-sealing key (used to open the backup).
    masked_sealing_key: Vec<u8>,
    /// Sender attestation evidence (OOB items + descriptors).  In a
    /// self-backup this is the same evidence `CreateSD` used.
    evidence: ReceiverEvidence,
    /// The 484-byte `PartPolicy` image.
    policy: [u8; PART_POLICY_LEN],
    /// `pok_remote_backup` from `CreateSD` — the HPKE seal to restore.
    src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],
    /// `sd_mk_backup` from `CreateSD` — the previous SDMK backup.
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a backing partition, `CreateSD`, and capture
/// everything device 2 needs to restore the domain remotely.
fn create_remote_backup(seed: &[u8], sata: &CaKey, pota: &PotaFixture) -> RemoteBackup {
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);

    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );

    let init = ctx
        .part_init(&session, seed, &policy, pota.thumbprint())
        .expect("PartInit");
    let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, sata, &report);
    let req = backup_request(session.session_id, masked.clone(), &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    RemoteBackup {
        masked_sealing_key: masked,
        evidence,
        policy,
        src_remote_backup: resp.pok_remote_backup,
        prev_sd_mk_backup: resp.sd_mk_backup,
        local_mk_backup,
    }
}

/// Assemble a `SdRestoreRemoteBackup` request from a captured backup.
fn restore_remote_req(session_id: u16, backup: &RemoteBackup) -> TborSdRestoreRemoteBackupReq {
    TborSdRestoreRemoteBackupReq {
        session_id,
        masked_sealing_key: backup
            .masked_sealing_key
            .as_slice()
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(&backup.policy).expect("policy image is canonical"),
        sender_mfgr_cert_chain: backup.evidence.mfgr.clone(),
        sender_owner_cert_chain: backup.evidence.owner.clone(),
        sender_part_owner_cert_chain: backup.evidence.part_owner.clone(),
        sender_report: backup.evidence.report,
        src_remote_backup: backup.src_remote_backup,
        prev_sd_mk_backup: backup.prev_sd_mk_backup,
    }
}

#[test]
fn sd_restore_remote_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = PotaFixture::generate();

    // Device 1: finalize + CreateSD, capturing the remote backup.
    let backup = create_remote_backup(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK (so the captured sealing key
    // unmasks), then restore the SD from the remote backup.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &backup.policy, pota.thumbprint())
        .expect("PartInit (device 2)");
    let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");

    let req = restore_remote_req(session.session_id, &backup);
    let resp = ctx
        .tbor_oob(&req, &backup.evidence.oob())
        .expect("SdRestoreRemoteBackup roundtrip");

    // Local backup (BKS3 masked under PartLocalMK), 180 B, non-zero.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 164 B.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

#[test]
fn sd_restore_remote_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = PotaFixture::generate();

    // A single device that has just created its SD is already
    // SD-initialized, so a remote restore on the same incarnation is
    // rejected by the one-shot gate.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let info = ctx.tbor(&TborPartInfoReq::new()).expect("PartInfo");
    let mut pid_pub = [0u8; RAW_PUB_LEN];
    pid_pub.copy_from_slice(&info.pid_pub_key);
    let policy = backing_part_policy(
        &info.pid,
        &info.pid_pub_key,
        &sata.raw_pub(),
        &pota.raw_pub(),
    );
    let init = ctx
        .part_init(&session, &seed, &policy, pota.thumbprint())
        .expect("PartInit");
    let chain = pota.chain_for(&pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let create_req = backup_request(session.session_id, masked.clone(), &evidence, &policy);
    let created = ctx
        .tbor_oob(&create_req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    let backup = RemoteBackup {
        masked_sealing_key: masked,
        evidence,
        policy,
        src_remote_backup: created.pok_remote_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
        local_mk_backup: Vec::new(),
    };
    let req = restore_remote_req(session.session_id, &backup);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_remote_backup_rejects_before_finalize() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdRestoreRemoteBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; 180],
        policy: PartPolicy::zeroed(),
        sender_mfgr_cert_chain: Vec::new(),
        sender_owner_cert_chain: Vec::new(),
        sender_part_owner_cert_chain: Vec::new(),
        sender_report: Default::default(),
        src_remote_backup: [0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
