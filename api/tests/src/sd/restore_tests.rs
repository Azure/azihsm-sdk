// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdRestoreRemoteBackup` round trip against the emulator or
//! hardware backend.
//!
//! Self-backup "reboot" flow: a first partition incarnation finalizes and
//! creates a remote backup (capturing its `pok_remote_backup` /
//! `sd_mk_backup` and the `local_mk_backup` from `part_final`), then a
//! second incarnation of the same partition — factory-reset with the same
//! deterministic machine seed — restores `PartLocalMK` via `part_final` (so
//! the captured sealing key unmasks) and restores the security domain from
//! the remote backup. A successful restore is itself the correctness check:
//! the HPKE open only succeeds if the receiver key and attested sender key
//! match those that sealed the backup.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;

/// Happy path: create a remote backup on one incarnation, then restore it
/// on a rebooted (factory-reset, same-seed) incarnation; the restore
/// returns non-zero refreshed device-local backups of the pinned lengths.
#[test]
fn sd_restore_remote_backup_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1: finalize + create, capturing the remote backup and the
    // local_mk backup needed to restore PartLocalMK after reboot.
    let (session1, policy, pid_pub, local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let created = evidence
        .with_hsm_evidence(|ev| session1.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");
    drop(session1);

    // Device 2 (reboot, same seed): restore PartLocalMK from device 1's
    // backup, then restore the security domain from the remote backup.
    let (session2, _policy2, _pid_pub2, _lmk2) =
        provision_backing(&sata, &pota, Some(policy), Some(&local_mk));
    let restored = evidence
        .with_hsm_evidence(|ev| {
            session2.sd_restore_remote_backup(
                &masked,
                ev,
                &policy,
                &created.pok_remote_backup,
                &created.sd_mk_backup,
            )
        })
        .expect("restore remote backup");

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
/// already SD-initialized, so a restore on that same incarnation is
/// rejected by the firmware's one-shot gate.
#[test]
fn sd_restore_remote_backup_is_one_shot() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let (session, policy, pid_pub, _local_mk) = provision_backing(&sata, &pota, None, None);
    let (masked, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let created = evidence
        .with_hsm_evidence(|ev| session.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");

    let restored = evidence.with_hsm_evidence(|ev| {
        session.sd_restore_remote_backup(
            &masked,
            ev,
            &policy,
            &created.pok_remote_backup,
            &created.sd_mk_backup,
        )
    });
    assert!(
        matches!(restored, Err(HsmError::SdAlreadyInitialized)),
        "restore on an already-initialized SD must be rejected with \
         SdAlreadyInitialized, got {restored:?}",
    );
}
