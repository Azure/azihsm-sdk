// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdCreateRemoteBackup` round trip against the emulator.
//!
//! Drives the full public-surface flow: provision a partition whose policy
//! names itself as the backup backing partition
//! ([`crate::utils::sd_provision::finalized_backing_session`]), mint an SD sealing
//! key, attest it via the masked-blob `KeyReport`, build the receiver's
//! three-chain attestation evidence, then call
//! [`HsmSession::sd_create_remote_backup`] and validate the three returned
//! backups. This is a **self-backup** (sender == receiver): the partition
//! seals to its own attested identity key.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::emu_helpers::EMU_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::finalized_backing_session;
use crate::utils::sd_provision::masked_key_and_report;

/// Happy path: creating a security domain on a partition that names
/// itself as the backing partition returns three non-zero backups of the
/// pinned wire lengths.
#[test]
fn sd_create_remote_backup_roundtrip() {
    let _guard = EMU_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    let (masked, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);
    let result = evidence
        .with_hsm_evidence(|receiver| session.sd_create_remote_backup(&masked, receiver, &policy))
        .expect("create remote backup");

    // Remote backup: HPKE-Auth seal of BKS3, 161 B, non-zero.
    assert_eq!(result.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        result.pok_remote_backup.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );

    // Local backup: BKS3 masked under the partition-local key, 180 B,
    // non-zero.
    assert_eq!(result.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        result.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );

    // Masking-key backup: SDMK masked under the derived SDBMK, 164 B,
    // non-zero.
    assert_eq!(result.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        result.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// One-shot: creating a security domain is a once-per-partition
/// operation, so a second `sd_create_remote_backup` on the now-initialized
/// partition is rejected by the firmware.
#[test]
fn sd_create_remote_backup_is_one_shot() {
    let _guard = EMU_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    let (masked, report) = masked_key_and_report(&session);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);

    evidence
        .with_hsm_evidence(|receiver| session.sd_create_remote_backup(&masked, receiver, &policy))
        .expect("first create remote backup");

    // A second create on the same (now initialized) partition must fail.
    let second = evidence
        .with_hsm_evidence(|receiver| session.sd_create_remote_backup(&masked, receiver, &policy));
    assert!(
        matches!(second, Err(HsmError::SdAlreadyInitialized)),
        "second create on an initialized partition must be rejected with \
         SdAlreadyInitialized, got {second:?}",
    );
}
