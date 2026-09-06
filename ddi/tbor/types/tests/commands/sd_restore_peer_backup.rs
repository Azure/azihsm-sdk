// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestorePeerBackup` command.
//!
//! `SdRestorePeerBackup` restores a security domain from a **peer** backup:
//! it HPKE-Auth-opens the caller-supplied `pok_peer_backup` (an HPKE seal
//! of BKS3) with the receiver's masked SD-sealing key — authenticated by
//! the sender peer's attested key — recovers `SDMK` from `prev_sd_mk_backup`,
//! and returns the device-local backups.  It is `SdRestoreRemoteBackup`
//! plus an `allow_peer_cloning` policy gate.
//!
//! The **round-trip** test uses a self-peer backup (sender == receiver): a
//! first device finalizes, `CreateSD`s, and `CreatePeerBackup`s (producing
//! the `pok_peer_backup` / `prev_sd_mk_backup` this command consumes, plus
//! the `local_mk_backup`), then a second device (factory-reset, same machine
//! seed) restores `PartLocalMK` via `PartFinal` — so it can unmask the
//! captured sealing key — and restores the security domain from the peer
//! backup.
//!
//! Coverage:
//! * Round-trip — create-peer → reboot → PartFinal(restore PartLocalMK) →
//!   restore-peer returns non-zero refreshed local backups.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Policy without `allow_peer_cloning` → `SdPeerCloningNotAllowed`.
//! * Restore before finalize → `InvalidArg`.

#![cfg(feature = "emu")]

use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborSdRestorePeerBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use zerocopy::TryFromBytes;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_peer_backup::create_peer_req;
use crate::commands::sd_create_peer_backup::finalize_peer_partition;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::commands::sd_create_remote_backup::ReceiverEvidence;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// A peer backup produced by the first device's `CreatePeerBackup`,
/// replayed on the second (rebooted) device to restore the security domain.
struct PeerBackup {
    /// The receiver's masked SD-sealing key (used to open the backup).
    masked_sealing_key: Vec<u8>,
    /// Sender attestation evidence (OOB items + descriptors).  In a
    /// self-peer backup this is the same evidence the seal used.
    evidence: ReceiverEvidence,
    /// The 484-byte `PartPolicy` image (with `allow_peer_cloning` set).
    policy: [u8; PART_POLICY_LEN],
    /// `pok_peer_backup` from `CreatePeerBackup` — the HPKE seal to restore.
    pok_peer_backup: [u8; POK_REMOTE_BACKUP_LEN],
    /// `sd_mk_backup` from `CreateSD` — the previous SDMK backup.
    prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a cloning-enabled backing partition, `CreateSD`,
/// and `CreatePeerBackup`, capturing everything device 2 needs to restore
/// the domain from the peer backup.
fn create_peer_backup(seed: &[u8], sata: &CaKey, pota: &CaKey) -> PeerBackup {
    let ctx = TestCtx::new();
    let part = finalize_peer_partition(&ctx, seed, sata, pota, true);
    let session_id = part.session.session_id;

    let (masked, report) = masked_key_and_report(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");
    let peer = ctx
        .tbor_oob(
            &create_peer_req(
                session_id,
                &masked,
                &evidence,
                &part.policy,
                &created.pok_local_backup,
            ),
            &evidence.oob(),
        )
        .expect("SdCreatePeerBackup");

    PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: peer.pok_peer_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
        local_mk_backup: part.local_mk_backup,
    }
}

/// Assemble a `SdRestorePeerBackup` request from a captured backup.
fn restore_peer_req(session_id: u16, backup: &PeerBackup) -> TborSdRestorePeerBackupReq {
    TborSdRestorePeerBackupReq {
        session_id,
        masked_sealing_key: backup
            .masked_sealing_key
            .as_slice()
            .try_into()
            .expect("masked sealing key is exactly MASKED_SEALING_KEY_LEN bytes"),
        policy: PartPolicy::try_read_from_bytes(&backup.policy).expect("policy image is canonical"),
        src_mfgr_cert_chain: backup.evidence.mfgr.clone(),
        src_owner_cert_chain: backup.evidence.owner.clone(),
        src_part_owner_cert_chain: backup.evidence.part_owner.clone(),
        src_report: backup.evidence.report,
        pok_peer_backup: backup.pok_peer_backup,
        prev_sd_mk_backup: backup.prev_sd_mk_backup,
    }
}

#[test]
fn sd_restore_peer_backup_roundtrip_emu() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + CreateSD + CreatePeerBackup, capturing the peer
    // backup.
    let backup = create_peer_backup(&seed, &sata, &pota);

    // Device 2 (reboot): restore PartLocalMK (so the captured sealing key
    // unmasks), then restore the SD from the peer backup.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, &seed, &backup.policy, &pota_thumbprint())
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &backup.policy,
        &backup.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");

    let req = restore_peer_req(session.session_id, &backup);
    let resp = ctx
        .tbor_oob(&req, &backup.evidence.oob())
        .expect("SdRestorePeerBackup roundtrip");

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
fn sd_restore_peer_backup_is_one_shot_emu() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD (via CreateSD) is already
    // SD-initialized, so a peer restore on the same incarnation is rejected
    // by the one-shot gate.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, true);
    let session_id = part.session.session_id;

    let (masked, report) = masked_key_and_report(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &sata, &report);
    let created = ctx
        .tbor_oob(
            &backup_request(session_id, masked.clone(), &evidence, &part.policy),
            &evidence.oob(),
        )
        .expect("SdCreateRemoteBackup");
    let peer = ctx
        .tbor_oob(
            &create_peer_req(
                session_id,
                &masked,
                &evidence,
                &part.policy,
                &created.pok_local_backup,
            ),
            &evidence.oob(),
        )
        .expect("SdCreatePeerBackup");

    let backup = PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: peer.pok_peer_backup,
        prev_sd_mk_backup: created.sd_mk_backup,
        local_mk_backup: Vec::new(),
    };
    let req = restore_peer_req(session_id, &backup);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdAlreadyInitialized,
    );
}

#[test]
fn sd_restore_peer_backup_rejects_without_peer_cloning_emu() {
    let ctx = TestCtx::new();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Finalize with a policy that does NOT opt into peer cloning.  The
    // peer-cloning gate fires in phase 1 (after the policy-hash re-check)
    // before any HPKE work, so dummy backup blobs are sufficient — but a
    // real sealing key and OOB evidence are needed to reach the gate.
    let part = finalize_peer_partition(&ctx, &mach_seed(), &sata, &pota, false);
    let session_id = part.session.session_id;

    let (masked, report) = masked_key_and_report(&ctx, session_id);
    let evidence = build_receiver_evidence(&part.pid_pub, &sata, &report);
    let backup = PeerBackup {
        masked_sealing_key: masked,
        evidence,
        policy: part.policy,
        pok_peer_backup: [0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
        local_mk_backup: Vec::new(),
    };
    let req = restore_peer_req(session_id, &backup);
    ctx.expect_fw_reject_oob(
        &req,
        &backup.evidence.oob(),
        TborStatus::SdPeerCloningNotAllowed,
    );
}

#[test]
fn sd_restore_peer_backup_rejects_before_finalize_emu() {
    // A partition that has not been finalized is rejected at the lifecycle
    // gate before any evidence or crypto work.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    let req = TborSdRestorePeerBackupReq {
        session_id: session.session_id,
        masked_sealing_key: [0u8; 180],
        policy: PartPolicy::zeroed(),
        src_mfgr_cert_chain: Vec::new(),
        src_owner_cert_chain: Vec::new(),
        src_part_owner_cert_chain: Vec::new(),
        src_report: Default::default(),
        pok_peer_backup: [0u8; POK_REMOTE_BACKUP_LEN],
        prev_sd_mk_backup: [0u8; SD_MK_BACKUP_LEN],
    };
    ctx.expect_fw_reject(&req, TborStatus::InvalidArg);
}
