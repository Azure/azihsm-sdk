// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdCreateRemoteBackup` / `SdRestoreRemoteBackup` tests for the
//! **trusted Sealing Authority key** path, exercised against the emulator or
//! hardware backend.
//!
//! When the backing-partition policy sets `require_trusted_sa_key`, the
//! firmware validates the peer certificate chain (spec `RcvrCertChain` on
//! create, `SndrCertChain` on restore, anchored to the policy SATA key) to
//! recover the peer public key **and** the three-chain attestation evidence
//! (partition-owner chain anchored to the policy SAPOTA key). Create
//! requires the report to attest that same peer key; restore additionally
//! binds the report to the partition policy (report `policy_hash` must equal
//! `SHA-384(policy)`) and requires the report to attest the same `SndrPub`
//! recovered from the sender chain. These tests cover both happy paths and
//! each fail-closed rejection.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence_trusted;
use crate::utils::sd_provision::finalized_backing_session_trusted;
use crate::utils::sd_provision::masked_key_and_report;
use crate::utils::sd_provision::provision_backing;
use crate::utils::sd_provision::provision_backing_trusted;

/// Happy path: under a `require_trusted_sa_key` policy, a create whose
/// SAPOTA-anchored evidence report attests the same `RcvrPub` carried by
/// the SATA-anchored receiver certificate chain succeeds and returns three
/// non-zero backups of the pinned wire lengths.
#[test]
fn sd_create_remote_backup_trusted_sa_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session_trusted(&sata_key, &sapota_key);

    let (masked, rcvr_pub, report) = masked_key_and_report(&session);
    let evidence =
        build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata_key, &sapota_key, &report);
    let result = evidence
        .with_create_backup(|rcvr_chain, receiver| {
            session.sd_create_remote_backup(&policy, &masked, rcvr_chain, receiver)
        })
        .expect("create remote backup under trusted-SA policy");

    assert_eq!(result.pok_remote_backup.len(), POK_REMOTE_BACKUP_LEN);
    assert!(
        result.pok_remote_backup.iter().any(|&b| b != 0),
        "pok_remote_backup must not be all-zero",
    );

    assert_eq!(result.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        result.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );

    assert_eq!(result.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        result.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// Rejection: under a `require_trusted_sa_key` policy, if the receiver
/// certificate chain certifies a key different from the one the evidence
/// report attests, the firmware rejects the create — the attested key must
/// equal the recovered `RcvrPub`.
#[test]
fn sd_create_remote_backup_trusted_sa_rcvr_pub_mismatch_is_rejected() {
    let _guard = PARTITION_LOCK.lock();
    let sata_key = CaKey::generate();
    let sapota_key = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session_trusted(&sata_key, &sapota_key);

    let (masked, _rcvr_pub, report) = masked_key_and_report(&session);

    // The receiver certificate chain certifies an unrelated key, so the
    // recovered `RcvrPub` differs from the sealing key the report attests.
    let wrong_rcvr_pub = CaKey::generate().raw_pub();
    let evidence =
        build_receiver_evidence_trusted(&pid_pub, &wrong_rcvr_pub, &sata_key, &sapota_key, &report);

    let outcome = evidence.with_create_backup(|rcvr_chain, receiver| {
        session.sd_create_remote_backup(&policy, &masked, rcvr_chain, receiver)
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "a receiver chain whose key differs from the attested RcvrPub must \
         be rejected with InvalidArg, got {outcome:?}",
    );
}

/// Happy path: under a `require_trusted_sa_key` policy, a self-backup
/// round trip (create on one incarnation, restore on a rebooted,
/// factory-reset same-seed incarnation) succeeds when the SAPOTA-anchored
/// evidence report attests both the partition policy (`policy_hash ==
/// SHA-384(policy)`) and the same `SndrPub` carried by the SATA-anchored
/// sender certificate chain. The restore returns non-zero refreshed
/// device-local backups of the pinned wire lengths.
#[test]
fn sd_restore_remote_backup_trusted_sa_roundtrip() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();

    // Device 1 (trusted policy): finalize + create, capturing the remote
    // backup and the local_mk backup needed to restore PartLocalMK after
    // reboot.
    let (session1, policy, pid_pub, local_mk) =
        provision_backing_trusted(&sata, &sapota, &pota, None, None);
    let (masked, rcvr_pub, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata, &sapota, &report);
    let created = evidence
        .with_create_backup(|rcvr_chain, ev| {
            session1.sd_create_remote_backup(&policy, &masked, rcvr_chain, ev)
        })
        .expect("create remote backup under trusted-SA policy");
    drop(session1);

    // Device 2 (reboot, same seed, same trusted policy): restore the
    // security domain from the remote backup.
    let (session2, _policy2, _pid_pub2, _lmk2) =
        provision_backing_trusted(&sata, &sapota, &pota, Some(&policy), Some(&local_mk));
    let restored = evidence
        .with_create_backup(|sender_chain, ev| {
            session2.sd_restore_remote_backup(
                &policy,
                &masked,
                sender_chain,
                ev,
                &created.pok_remote_backup,
                &created.sd_mk_backup,
            )
        })
        .expect("restore remote backup under trusted-SA policy");

    assert_eq!(restored.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        restored.pok_local_backup.iter().any(|&b| b != 0),
        "pok_local_backup must not be all-zero",
    );
    assert_eq!(restored.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        restored.sd_mk_backup.iter().any(|&b| b != 0),
        "sd_mk_backup must not be all-zero",
    );
}

/// Rejection: under a `require_trusted_sa_key` policy, if the sender
/// certificate chain certifies a key different from the one the evidence
/// report attests, the restore is rejected — the attested key must equal
/// the recovered `SndrPub`. The rejection lands in phase 1, before any
/// security-domain state is touched, so dummy response-length backups
/// suffice.
#[test]
fn sd_restore_remote_backup_trusted_sa_sndr_pub_mismatch_is_rejected() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let (session, policy, pid_pub) = finalized_backing_session_trusted(&sata, &sapota);

    // The report attests the real sealing key `rcvr_pub`, but the sender
    // certificate chain certifies an unrelated key, so the recovered
    // `SndrPub` differs from the attested key.
    let (masked, _rcvr_pub, report) = masked_key_and_report(&session);
    let wrong_sndr_pub = CaKey::generate().raw_pub();
    let evidence =
        build_receiver_evidence_trusted(&pid_pub, &wrong_sndr_pub, &sata, &sapota, &report);

    let dummy_pok = vec![0u8; POK_REMOTE_BACKUP_LEN];
    let dummy_mk = vec![0u8; SD_MK_BACKUP_LEN];
    let outcome = evidence.with_create_backup(|sender_chain, ev| {
        session.sd_restore_remote_backup(&policy, &masked, sender_chain, ev, &dummy_pok, &dummy_mk)
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "a sender chain whose key differs from the attested SndrPub must \
         be rejected with InvalidArg, got {outcome:?}",
    );
}

/// Rejection: under a `require_trusted_sa_key` policy, the restore binds the
/// evidence report to the partition policy — the report `policy_hash` must
/// equal `SHA-384(policy)`. An evidence report generated while the same
/// partition was bound to a *different* policy is rejected, even though it
/// attests the correct `SndrPub`.
///
/// The partition is first bound to one policy and emits a sealing-key report
/// (whose attested `policy_hash` is that policy's hash), then factory-reset
/// and re-provisioned under a *trusted* policy; restoring under the trusted
/// policy makes `SHA-384(policy)` differ from the stale hash the report
/// carries, exercising the restore-only policy-binding check.
#[test]
fn sd_restore_remote_backup_trusted_sa_policy_hash_mismatch_is_rejected() {
    let _guard = PARTITION_LOCK.lock();
    let sata = CaKey::generate();
    let sapota = CaKey::generate();
    let pota = CaKey::generate();

    // Incarnation 1: bind the partition to a (non-trusted) policy and emit a
    // sealing-key report; its attested policy hash is SHA-384(that policy).
    let (session1, _policy1, pid_pub, _lmk1) = provision_backing(&sata, &pota, None, None);
    let (_masked1, rcvr_pub, report) = masked_key_and_report(&session1);
    let evidence = build_receiver_evidence_trusted(&pid_pub, &rcvr_pub, &sata, &sapota, &report);
    drop(session1);

    // Incarnation 2 (factory reset, same seed): re-provision the same
    // partition identity under a *trusted* policy. The restore binds to this
    // policy, so the expected SHA-384(policy) differs from the hash the
    // stale report attests.
    let (session2, policy2, _pid_pub2, _lmk2) =
        provision_backing_trusted(&sata, &sapota, &pota, None, None);
    let (masked2, _rcvr2, _report2) = masked_key_and_report(&session2);

    let dummy_pok = vec![0u8; POK_REMOTE_BACKUP_LEN];
    let dummy_mk = vec![0u8; SD_MK_BACKUP_LEN];
    let outcome = evidence.with_create_backup(|sender_chain, ev| {
        session2.sd_restore_remote_backup(
            &policy2,
            &masked2,
            sender_chain,
            ev,
            &dummy_pok,
            &dummy_mk,
        )
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "an evidence report whose attested policy_hash differs from \
         SHA-384(policy) must be rejected with InvalidArg, got {outcome:?}",
    );
}
