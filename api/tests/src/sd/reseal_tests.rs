// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdResealRemoteBackup` round trip against the emulator or
//! hardware backend.
//!
//! Self-reseal on one partition: mint receiver / sender / destination SD
//! sealing keys, use `sd_create_remote_backup` to produce a real source
//! backup (BKS3 sealed to the receiver by the sender), then reseal it to
//! the destination. A successful reseal is itself the correctness check —
//! the HPKE open only succeeds if the receiver key and the attested sender
//! key match those that sealed the source.

use azihsm_api::*;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::RAW_PUB_LEN;
use crate::utils::sd_provision::build_receiver_evidence;
use crate::utils::sd_provision::finalized_backing_session;
use crate::utils::sd_provision::masked_key_and_report;

/// Create a real source backup: a fresh BKS3 sealed to the receiver's
/// attested public key (`receiver_report`) by the `masked_sender_key`.
fn create_source_backup(
    session: &HsmSession,
    sata_key: &CaKey,
    pid_pub: &[u8; RAW_PUB_LEN],
    masked_sender_key: &[u8],
    receiver_report: &[u8],
    policy: &[u8],
) -> Vec<u8> {
    let receiver = build_receiver_evidence(pid_pub, sata_key, receiver_report);
    receiver
        .with_hsm_evidence(|rcvr| session.sd_create_remote_backup(masked_sender_key, rcvr, policy))
        .expect("source backup")
        .pok_remote_backup
}

/// Happy path: resealing a real source backup yields a fresh 161-byte,
/// non-zero backup distinct from the source ciphertext.
#[test]
fn sd_reseal_remote_backup_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    // Receiver (unseals the source), sender (sealed the source), and
    // destination (the reseal target) SD sealing keys, each attested.
    let (masked_rcvr, report_rcvr) = masked_key_and_report(&session);
    let (masked_sndr, report_sndr) = masked_key_and_report(&session);
    let (_masked_dst, report_dst) = masked_key_and_report(&session);

    let src_backup = create_source_backup(
        &session,
        &sata_key,
        &pid_pub,
        &masked_sndr,
        &report_rcvr,
        &policy,
    );

    // Reseal: open with the receiver key (auth = sender), reseal to the
    // destination receiver.
    let src_ev = build_receiver_evidence(&pid_pub, &sata_key, &report_sndr);
    let dst_ev = build_receiver_evidence(&pid_pub, &sata_key, &report_dst);
    let dst_backup = src_ev
        .with_hsm_evidence(|src| {
            dst_ev.with_hsm_evidence(|dest| {
                session.sd_reseal_remote_backup(&masked_rcvr, src, dest, &policy, &src_backup)
            })
        })
        .expect("reseal remote backup");

    // A successful HPKE open -> seal yields a 161-byte, non-zero backup.
    assert_eq!(dst_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        dst_backup.iter().any(|&b| b != 0),
        "dst_remote_backup must not be all-zero",
    );
    // The resealed backup is a fresh HPKE encapsulation, not the source.
    assert_ne!(
        dst_backup,
        src_backup.to_vec(),
        "reseal must produce a fresh encapsulation, not echo the source",
    );
}

/// Re-randomization: two reseals of the same source produce distinct
/// ciphertexts (a fresh HPKE ephemeral each call).
#[test]
fn sd_reseal_remote_backup_rerandomizes() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session(&sata_key);

    let (masked_rcvr, report_rcvr) = masked_key_and_report(&session);
    let (masked_sndr, report_sndr) = masked_key_and_report(&session);
    let (_masked_dst, report_dst) = masked_key_and_report(&session);

    let src_backup = create_source_backup(
        &session,
        &sata_key,
        &pid_pub,
        &masked_sndr,
        &report_rcvr,
        &policy,
    );

    let src_ev = build_receiver_evidence(&pid_pub, &sata_key, &report_sndr);
    let dst_ev = build_receiver_evidence(&pid_pub, &sata_key, &report_dst);
    let reseal = || {
        src_ev
            .with_hsm_evidence(|src| {
                dst_ev.with_hsm_evidence(|dest| {
                    session.sd_reseal_remote_backup(&masked_rcvr, src, dest, &policy, &src_backup)
                })
            })
            .expect("reseal remote backup")
    };

    let first = reseal();
    let second = reseal();
    assert_ne!(
        first, second,
        "each reseal must re-randomize the HPKE encapsulation",
    );
}
