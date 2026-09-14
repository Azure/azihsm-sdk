// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! api-level `SdCreateRemoteBackup` tests for the **trusted Sealing
//! Authority key** path, exercised against the emulator or hardware
//! backend.
//!
//! When the backing-partition policy sets `require_trusted_sa_key`, the
//! firmware validates the receiver certificate chain (spec `RcvrCertChain`,
//! anchored to the policy SATA key) to recover `RcvrPub` **and** the
//! three-chain attestation evidence (spec `RcvrEvidence`, partition-owner
//! chain anchored to the policy SAPOTA key), requiring the report to attest
//! that same `RcvrPub`. These tests cover the happy path and the
//! `RcvrPub`-mismatch rejection.

use azihsm_api::*;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::POK_REMOTE_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::utils::partition_ex_helpers::PARTITION_LOCK;
use crate::utils::sd_provision::CaKey;
use crate::utils::sd_provision::build_receiver_evidence_trusted;
use crate::utils::sd_provision::finalized_backing_session_trusted;
use crate::utils::sd_provision::masked_key_and_report;

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
            session.sd_create_remote_backup(&masked, rcvr_chain, receiver, &policy)
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
        session.sd_create_remote_backup(&masked, rcvr_chain, receiver, &policy)
    });
    assert!(
        matches!(outcome, Err(HsmError::InvalidArgument)),
        "a receiver chain whose key differs from the attested RcvrPub must \
         be rejected with InvalidArg, got {outcome:?}",
    );
}
