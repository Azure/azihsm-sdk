// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` write-once claim.
//!
//! `SD_MK_KEY_ID` is the sole completion witness, published before the
//! response is handed back, so a second restore on the same incarnation
//! is refused. These tests pin all four consequences: the direct second
//! attempt, a replayed request after a delivered success, concurrent
//! callers resolving to one winner, and -- the inverse -- a *rejected*
//! attempt leaving the claim unconsumed so a valid retry still succeeds.

use std::sync::Barrier;

use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use super::assert_refreshed_pair;
use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;
use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::harness::assertions::assert_fw_rejects;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// A device that has just created its SD is already SD-initialized, so a
/// local restore on the same incarnation must be refused by the one-shot
/// gate with [`TborStatus::SdAlreadyInitialized`].
#[test]
fn sd_restore_local_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

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
        .part_init(&session, &seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(&pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal");

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, &sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let created = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.to_vec(),
            sd_mk_backup: created.sd_mk_backup.to_vec(),
        },
        TborStatus::SdAlreadyInitialized,
    );
}

/// A host that loses the reply cannot reissue the command: state commits
/// before the response is delivered, so the retry sees an initialized
/// domain and gets [`TborStatus::SdAlreadyInitialized`].
///
/// That is deliberate, not an oversight -- see
/// `docs/tbor-ddi/commands/sd_restore_local_backup.md`. Pinning it here
/// forces any future move to idempotent replay to revisit this test on
/// purpose rather than silently change the contract.
#[test]
fn sd_restore_local_backup_rejects_replay_after_success() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let req = TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup.clone(),
        sd_mk_backup: created.sd_mk_backup.clone(),
    };
    let resp = ctx.tbor(&req).expect("first SdRestoreLocalBackup");
    assert_refreshed_pair(&resp.pok_local_backup, &resp.sd_mk_backup);

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::SdAlreadyInitialized,
    );
}

/// A rejected attempt must leave the claim unconsumed, so a valid retry
/// on the same session still succeeds.
///
/// `SD_MK_KEY_ID` is published only once the command is past every unmask
/// and has its response encoded, so a failure this early can never mark
/// the domain initialized. Were that ordering to regress, the retry below
/// would come back [`TborStatus::SdAlreadyInitialized`] and the device
/// would be unrecoverable in the field after a single malformed request.
#[test]
fn sd_restore_local_backup_retry_after_rejected_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    // First attempt fails the AEAD tag check on `sd_mk_backup`.
    let mut tampered = created.sd_mk_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: tampered,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("retry after a rejected restore must succeed");
    assert_refreshed_pair(&resp.pok_local_backup, &resp.sd_mk_backup);
}

/// Sixteen threads share one CO session and race `SdRestoreLocalBackup`
/// on a freshly recovered device.
///
/// Exactly one may restore the security domain; every other request must
/// get [`TborStatus::SdAlreadyInitialized`] from the `sd_initialized()`
/// gate in `on_start`, which is authoritative because
/// `commit_sd_restore_state` publishes `SD_MK_KEY_ID` before the winner's
/// response is handed back. The claim is therefore held by partition
/// state rather than an in-FSM flag.
#[test]
fn sd_restore_local_backup_multi_threaded_single_winner() {
    const THREAD_COUNT: usize = 16;

    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    let barrier = Barrier::new(THREAD_COUNT);

    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREAD_COUNT)
            .map(|_| {
                let barrier = &barrier;
                let worker_ctx = &ctx;
                let created = &created;
                let session_id = session.session_id;

                scope.spawn(move || {
                    let req = TborSdRestoreLocalBackupReq {
                        session_id,
                        pok_local_backup: created.pok_local_backup.clone(),
                        sd_mk_backup: created.sd_mk_backup.clone(),
                    };
                    barrier.wait();
                    worker_ctx.tbor(&req)
                })
            })
            .collect();

        handles
            .into_iter()
            .map(|handle| handle.join().expect("worker thread must not panic"))
            .collect()
    });

    let (winners, rejections): (Vec<_>, Vec<_>) = results.into_iter().partition(Result::is_ok);

    assert_eq!(
        winners.len(),
        1,
        "exactly one concurrent SdRestoreLocalBackup must succeed",
    );
    assert_eq!(
        rejections.len(),
        THREAD_COUNT - 1,
        "every non-winning SdRestoreLocalBackup must be rejected",
    );

    // Same status the sequential `sd_restore_local_backup_is_one_shot` pins.
    for err in rejections.into_iter().map(Result::unwrap_err) {
        assert_fw_rejects(&err, TborStatus::SdAlreadyInitialized);
    }

    // The winner's output must still be well-formed: a loser that wrongly
    // reached the staging path would have run rollback and torn down the
    // security domain the winner just published.
    let winner = winners
        .into_iter()
        .next()
        .expect("checked above")
        .expect("winner is Ok");
    assert_refreshed_pair(&winner.pok_local_backup, &winner.sd_mk_backup);
}

/// A rejected restore must leave the observable partition state exactly
/// as it found it.
///
/// `commit_sd_established_state` publishes the claim before the response
/// is handed back, so a command that never reaches the commit must not
/// advance the lifecycle state, bump the generation, or roll the owner
/// seed. If a refused restore moved any of them, every later gate would
/// be judging the wrong state.
#[test]
fn sd_restore_local_backup_rejection_does_not_mutate_partition_state() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let before = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo before rejection");

    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: vec![0u8; MASKED_SD_LEN],
        sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
    })
    .expect_err("a malformed restore must be rejected");

    let after = ctx
        .tbor(&TborPartInfoReq::new())
        .expect("PartInfo after rejection");

    assert_eq!(
        after.part_state, before.part_state,
        "a rejected restore must not advance the partition lifecycle state",
    );
    assert_eq!(
        after.generation, before.generation,
        "a rejected restore must not bump the partition generation",
    );
    assert_eq!(
        after.owner_svn, before.owner_svn,
        "a rejected restore must not roll the owner seed",
    );
}

/// Three distinct failure modes in sequence, then a valid restore.
///
/// The one-shot claim must survive a run of rejections, which is what a
/// partition sees when a host replays a stale or corrupted backup pair.
#[test]
fn sd_restore_local_backup_multiple_rejections_do_not_consume_the_claim() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered_pok = created.pok_local_backup.clone();
    let last = tampered_pok.len() - 1;
    tampered_pok[last] ^= 0xFF;

    let mut tampered_sd_mk = created.sd_mk_backup.clone();
    let last = tampered_sd_mk.len() - 1;
    tampered_sd_mk[last] ^= 0xFF;

    let attempts: [(Vec<u8>, Vec<u8>); 3] = [
        (vec![0u8; MASKED_SD_LEN], created.sd_mk_backup.clone()),
        (tampered_pok, created.sd_mk_backup.clone()),
        (created.pok_local_backup.clone(), tampered_sd_mk),
    ];

    for (pok, sd_mk) in attempts {
        ctx.tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: pok,
            sd_mk_backup: sd_mk,
        })
        .expect_err("each malformed restore must be rejected");
    }

    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup.clone(),
        sd_mk_backup: created.sd_mk_backup.clone(),
    })
    .expect("a valid restore must still succeed after repeated rejections");
}

/// A rejected restore must not tear down the session it arrived on.
///
/// The command runs in-session and the dispatcher binds the SQE to the
/// session id, so a handler that closed or poisoned the slot on the error
/// path would strand the host with no way to retry.
#[test]
fn sd_restore_local_backup_session_remains_usable_after_rejection() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: vec![0u8; MASKED_SD_LEN],
        sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
    })
    .expect_err("a malformed restore must be rejected");

    // Same session, valid request: proves the slot is still Active.
    ctx.tbor(&TborSdRestoreLocalBackupReq {
        session_id: session.session_id,
        pok_local_backup: created.pok_local_backup.clone(),
        sd_mk_backup: created.sd_mk_backup.clone(),
    })
    .expect("the session must still serve a valid restore after a rejection");
}
