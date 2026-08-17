// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdRestorePeerBackup` round trip against the emulator or
//! hardware backend.
//!
//! Self-backup "reboot" flow: a first partition incarnation finalizes,
//! creates the security domain, and creates a **peer** backup of it
//! (capturing `pok_peer_backup`, `sd_mk_backup`, and the `local_mk_backup`
//! from `part_final`), then a second incarnation of the same partition —
//! factory-reset with the same deterministic machine seed — restores
//! `PartLocalMK` via `part_final` (so the captured sealing key unmasks) and
//! restores the security domain from the peer backup. A successful restore
//! is itself the correctness check: the HPKE open only succeeds if the
//! receiver key and attested source-peer key match those that sealed the
//! backup.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;
use crate::utils::sd_provision::provision_backing_ex;

/// Happy path: create a peer backup on one incarnation, then restore it on
/// a rebooted (factory-reset, same-seed) incarnation; the restore returns
/// non-zero refreshed device-local backups of the pinned lengths.
#[test]
fn sd_restore_peer_backup_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize, create the SD, and create a peer backup of it,
    // capturing the peer backup plus the sd_mk / local_mk backups device 2
    // needs to restore.
    let (session1, policy, pid_pub, local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let created = evidence
        .with_hsm_evidence(|ev| session1.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");
    // Self-peer backup: seal to our own attested identity as destination.
    let pok_peer_backup = evidence
        .with_hsm_evidence(|dst| {
            session1.sd_create_peer_backup(&masked, dst, &policy, &created.pok_local_backup)
        })
        .expect("create peer backup");
    drop(session1);

    // Device 2 (reboot, same seed): restore PartLocalMK from device 1's
    // backup, then restore the security domain from the peer backup.
    let (session2, _policy2, _pid_pub2, _lmk2) =
        provision_backing(&sata, &pota, Some(policy), Some(&local_mk));
    let restored = evidence
        .with_hsm_evidence(|src| {
            session2.sd_restore_peer_backup(
                &masked,
                src,
                &policy,
                &pok_peer_backup,
                &created.sd_mk_backup,
            )
        })
        .expect("restore peer backup");

    // Local backup (BKS3 re-masked under PartLocalMK), 180 B, non-zero.
    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        restored.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 164 B.
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        restored.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// One-shot: an incarnation that just created its security domain is
/// already SD-initialized, so a peer restore on that same incarnation is
/// rejected by the firmware's one-shot gate.
#[test]
fn sd_restore_peer_backup_is_one_shot() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let (session, policy, pid_pub, _local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let created = evidence
        .with_hsm_evidence(|ev| session.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");
    let pok_peer_backup = evidence
        .with_hsm_evidence(|dst| {
            session.sd_create_peer_backup(&masked, dst, &policy, &created.pok_local_backup)
        })
        .expect("create peer backup");

    let restored = evidence.with_hsm_evidence(|src| {
        session.sd_restore_peer_backup(
            &masked,
            src,
            &policy,
            &pok_peer_backup,
            &created.sd_mk_backup,
        )
    });
    assert!(
        matches!(restored, Err(HsmError::SdAlreadyInitialized)),
        "restore on an already-initialized SD must be rejected with \
         SdAlreadyInitialized, got {restored:?}",
    );
}

/// Not permitted: a partition finalized with `allow_peer_cloning` cleared
/// rejects `SdRestorePeerBackup` at the policy gate, which fires before any
/// HPKE work — so a real sealing key and evidence reach the gate but the
/// backup blobs can be zero-filled placeholders.
#[test]
fn sd_restore_peer_backup_rejects_without_peer_cloning() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let (session, policy, pid_pub, _local_mk) =
        provision_backing_ex(&sata, &pota, None, None, false);
    let (masked, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);

    let pok_peer_backup = [0u8; POK_REMOTE_BACKUP_LEN];
    let prev_sd_mk_backup = [0u8; SD_MK_BACKUP_LEN];
    let restored = evidence.with_hsm_evidence(|src| {
        session.sd_restore_peer_backup(&masked, src, &policy, &pok_peer_backup, &prev_sd_mk_backup)
    });
    assert!(
        matches!(restored, Err(HsmError::SdPeerCloningNotAllowed)),
        "restore with allow_peer_cloning cleared must be rejected with \
         SdPeerCloningNotAllowed, got {restored:?}",
    );
}
