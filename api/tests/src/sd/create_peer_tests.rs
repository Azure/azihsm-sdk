// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdCreatePeerBackup` round trip against the emulator or
//! hardware backend.
//!
//! Provision a peer-cloning-enabled backing partition, `CreateSD`
//! ([`HsmSession::sd_create_remote_backup`]) to obtain the device-local
//! backup, then [`HsmSession::sd_create_peer_backup`] to HPKE-Auth-seal
//! BKS3 to the destination peer. This is a **self-peer** backup (sender ==
//! destination): the partition seals to its own attested identity key, so a
//! successful seal is itself the correctness check.

use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::finalized_backing_session;
use crate::utils::sd_provision::masked_key_and_report;

/// Happy path: create the security domain, then a peer backup of it; the
/// peer backup is a non-zero 161-byte HPKE-Auth seal.
#[test]
fn sd_create_peer_backup_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    let (masked, report) = masked_key_and_report(&session, &policy);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);

    // Create the security domain first to obtain the device-local backup
    // that CreatePeerBackup recovers BKS3 from.
    let created = evidence
        .with_hsm_evidence(|ev| session.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");

    // Self-peer backup: seal to our own attested identity as destination.
    let peer = evidence
        .with_hsm_evidence(|dst| {
            session.sd_create_peer_backup(&masked, dst, &policy, &created.pok_local_backup)
        })
        .expect("create peer backup");

    // Peer backup: HPKE-Auth seal of BKS3, 161 B, non-zero.
    assert_eq!(peer.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        peer.iter().any(|&b| b != 0),
        "pok_peer_backup must not be all-zero",
    );
}

/// Re-randomization: two peer backups of the same domain produce distinct
/// ciphertexts (a fresh HPKE ephemeral each call). Peer backup is not a
/// one-shot, so the second call is expected to succeed.
#[test]
fn sd_create_peer_backup_rerandomizes() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    let (masked, report) = masked_key_and_report(&session, &policy);
    let evidence = build_receiver_evidence(&pid_pub, &sata_key, &report);

    let created = evidence
        .with_hsm_evidence(|ev| session.sd_create_remote_backup(&masked, ev, &policy))
        .expect("create remote backup");

    let first = evidence
        .with_hsm_evidence(|dst| {
            session.sd_create_peer_backup(&masked, dst, &policy, &created.pok_local_backup)
        })
        .expect("create peer backup");
    let second = evidence
        .with_hsm_evidence(|dst| {
            session.sd_create_peer_backup(&masked, dst, &policy, &created.pok_local_backup)
        })
        .expect("create peer backup");

    assert_eq!(first.len(), POK_REMOTE_BACKUP_LEN);
    assert_ne!(
        first, second,
        "each peer backup must re-randomize the HPKE seal",
    );
}
