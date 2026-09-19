// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreLocalBackup` command.
//!
//! `SdRestoreLocalBackup` restores a security domain from its device-local
//! backups (`pok_local_backup` = BKS3 masked under `PartLocalMK`,
//! `sd_mk_backup` = SDMK masked under the derived SDBMK), re-masks both at
//! the current SVN, and re-provisions the SD — the local-reboot recovery
//! path.  It needs no sender, HPKE, evidence, or out-of-band data.
//!
//! The **round-trip** test exercises the realistic recovery sequence on one
//! backend path: the first partition incarnation finalizes and `CreateSD`s
//! (capturing the local backups and `local_mk_backup`), the test explicitly
//! erases that partition, then a fresh handle restores `PartLocalMK` via
//! `PartFinal` and restores the security domain from the captured backups.
//!
//! Coverage:
//! * Round-trip — create → explicit partition reset → fresh handle →
//!   PartFinal(restore PartLocalMK) → restore-local.
//! * Functional proof — SecurityDomain-scoped sealing-key generation fails
//!   before restore and succeeds after restore.
//! * Refreshed-backup proof — a second reset and restore succeeds with the
//!   backups returned by the first restore.
//! * One-shot — restore onto an already-initialized SD → `SdAlreadyInitialized`.
//! * Restore before finalize → `InvalidArg`.
//! * A tampered `pok_local_backup` is rejected (AEAD tag mismatch).
//! * A tampered `sd_mk_backup` is rejected without publishing SDMK.

use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborSdSealingKeyGenReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::MASKED_SEALING_KEY_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;
use azihsm_ddi_tbor_types::SD_SEALING_PUB_KEY_LEN;

use crate::commands::part_init::mach_seed;
use crate::commands::part_init::pota_thumbprint;
use crate::commands::sd_create_remote_backup::backing_part_policy;
use crate::commands::sd_create_remote_backup::backup_request;
use crate::commands::sd_create_remote_backup::build_receiver_evidence;
use crate::commands::sd_create_remote_backup::masked_key_and_report;
use crate::harness::bootstrap_rotated_co;
use crate::harness::x509_fixture::make_pta_chain;
use crate::harness::x509_fixture::pta_pub_from_csr;
use crate::harness::x509_fixture::CaKey;
use crate::harness::x509_fixture::RAW_PUB_LEN;
use crate::harness::TestCtx;
use crate::harness::ROTATED_CO_PSK;

/// `KeyScope::SecurityDomain` wire discriminant.
const SCOPE_SECURITY_DOMAIN: u8 = 0b100;

/// Material captured from the first device's `CreateSD`, replayed on the
/// second (rebooted) device to restore the security domain.
struct CreatedSd {
    /// The exact 484-byte `PartPolicy` image (needed verbatim to
    /// re-finalize and to re-derive SDBMK on the second device).
    policy: [u8; azihsm_ddi_tbor_types::PART_POLICY_LEN],
    /// `PartFinal`'s `local_mk_backup`, replayed to restore `PartLocalMK`.
    local_mk_backup: Vec<u8>,
    /// The local SD backups from `CreateSD`.
    pok_local_backup: Vec<u8>,
    sd_mk_backup: Vec<u8>,
}

/// Drive device 1: finalize a backing partition, mint the SD via
/// `CreateSD`, and capture everything device 2 needs to recover.  The
/// `pota` / `sata` trust anchors and machine `seed` are supplied by the
/// caller so the second device can re-finalize with an identical policy /
/// certificate chain.
fn create_sd_on_first_device(ctx: &TestCtx, seed: &[u8], sata: &CaKey, pota: &CaKey) -> CreatedSd {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);

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
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report) = masked_key_and_report(ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    let created = CreatedSd {
        policy,
        local_mk_backup,
        pok_local_backup: resp.pok_local_backup.to_vec(),
        sd_mk_backup: resp.sd_mk_backup.to_vec(),
    };
    ctx.session_close(session.session_id)
        .expect("close first-incarnation session before reset");
    created
}

/// Drive device 2 (reboot): re-init with the same seed/policy, restore
/// `PartLocalMK` from `local_mk_backup`, and return the finalized session.
fn reboot_and_restore_part_local_mk(
    ctx: &TestCtx,
    seed: &[u8],
    pota: &CaKey,
    created: &CreatedSd,
) -> crate::harness::SessionHandshake {
    let session = bootstrap_rotated_co(ctx, &ROTATED_CO_PSK);
    let init = ctx
        .part_init(&session, seed, &created.policy, &pota_thumbprint())
        .expect("PartInit (device 2)");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    ctx.part_final(
        &session,
        &created.policy,
        &created.local_mk_backup,
        &chain.der_items(),
    )
    .expect("PartFinal must restore PartLocalMK from the prior backup");
    session
}

fn sd_scoped_sealing_key_request(session_id: u16) -> TborSdSealingKeyGenReq {
    TborSdSealingKeyGenReq {
        session_id,
        scope: SCOPE_SECURITY_DOMAIN,
    }
}

fn assert_sd_scoped_sealing_key_is_operational(ctx: &TestCtx, session_id: u16) {
    let resp = ctx
        .tbor(&sd_scoped_sealing_key_request(session_id))
        .expect("SecurityDomain-scoped sealing-key generation after restore");
    assert_eq!(
        resp.masked_key.len(),
        MASKED_SEALING_KEY_LEN,
        "masked sealing key must have the canonical envelope length",
    );
    assert!(
        resp.masked_key.iter().any(|&b| b != 0),
        "SecurityDomain-scoped masked sealing key must not be all-zero",
    );
    assert_eq!(
        resp.pub_key.len(),
        SD_SEALING_PUB_KEY_LEN,
        "sealing public key must have the canonical P-384 length",
    );
    assert!(
        resp.pub_key.iter().any(|&b| b != 0),
        "sealing public key must not be all-zero",
    );
}

#[test]
fn sd_restore_local_backup_after_explicit_partition_reset() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // First partition incarnation: finalize + CreateSD and retain every
    // host-persisted artifact needed after destructive reset.
    let ctx = TestCtx::new();
    let path = ctx.path().to_owned();
    let created = create_sd_on_first_device(&ctx, &seed, &sata, &pota);

    // Reset the same backend path. Use a fresh handle because the old handle
    // deliberately retains host-side session tracking for reopen semantics.
    ctx.erase().expect("explicit partition reset");
    let restored_ctx = TestCtx::new_with_path(&path);
    let session = reboot_and_restore_part_local_mk(&restored_ctx, &seed, &pota, &created);

    // PartFinal restored PartLocalMK, but SDMK must remain unavailable until
    // SdRestoreLocalBackup commits it.
    restored_ctx.expect_fw_reject(
        &sd_scoped_sealing_key_request(session.session_id),
        TborStatus::UnsupportedKeyScope,
    );

    let resp = restored_ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup.clone(),
            sd_mk_backup: created.sd_mk_backup.clone(),
        })
        .expect("SdRestoreLocalBackup roundtrip");

    // Refreshed local backup (BKS3 re-masked under PartLocalMK), 276 B.
    assert_eq!(resp.pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        resp.pok_local_backup.iter().any(|&b| b != 0),
        "refreshed pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 260 B.
    assert_eq!(resp.sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        resp.sd_mk_backup.iter().any(|&b| b != 0),
        "refreshed sd_mk_backup must not be all-zero",
    );

    // Functional acceptance check: this succeeds only when recovered SDMK is
    // active as the SecurityDomain masking key.
    assert_sd_scoped_sealing_key_is_operational(&restored_ctx, session.session_id);

    // Restore is one-shot within a partition incarnation.
    restored_ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: resp.pok_local_backup.clone(),
            sd_mk_backup: resp.sd_mk_backup.clone(),
        },
        TborStatus::SdAlreadyInitialized,
    );
    restored_ctx
        .session_close(session.session_id)
        .expect("close restored session before second reset");

    // Prove refreshed outputs are usable recovery artifacts by restoring from
    // them after another destructive reset.
    restored_ctx
        .erase()
        .expect("second explicit partition reset");
    let refreshed_ctx = TestCtx::new_with_path(&path);
    let refreshed_created = CreatedSd {
        policy: created.policy,
        local_mk_backup: created.local_mk_backup,
        pok_local_backup: resp.pok_local_backup,
        sd_mk_backup: resp.sd_mk_backup,
    };
    let refreshed_session =
        reboot_and_restore_part_local_mk(&refreshed_ctx, &seed, &pota, &refreshed_created);
    refreshed_ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: refreshed_session.session_id,
            pok_local_backup: refreshed_created.pok_local_backup,
            sd_mk_backup: refreshed_created.sd_mk_backup,
        })
        .expect("restore from refreshed local backups after second reset");
    assert_sd_scoped_sealing_key_is_operational(&refreshed_ctx, refreshed_session.session_id);
}

#[test]
fn sd_restore_local_backup_is_one_shot() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    // A single device that has just created its SD is already
    // SD-initialized, so a local restore on the same incarnation is
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

#[test]
fn sd_restore_local_backup_rejects_before_finalize() {
    // A partition that has not been finalized has no PartLocalMK, so the
    // command is rejected at the lifecycle gate before any unmask.
    let ctx = TestCtx::new();
    let session = bootstrap_rotated_co(&ctx, &ROTATED_CO_PSK);
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidArg,
    );
}

#[test]
fn sd_restore_local_backup_rejects_tampered_pok() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let create_ctx = TestCtx::new();
    let created = create_sd_on_first_device(&create_ctx, &seed, &sata, &pota);
    let path = create_ctx.path().to_owned();
    create_ctx.erase().expect("explicit partition reset");

    // Fresh incarnation: restore PartLocalMK, then attempt a restore with a
    // byte-flipped local backup — the AEAD tag no longer verifies.
    let ctx = TestCtx::new_with_path(&path);
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let mut tampered = created.pok_local_backup.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;

    // A byte-flipped local backup fails the AEAD tag check inside `unmask`;
    // assert the exact status so the contract is locked in — the command must
    // not succeed or provision the SD under any other failure mode.
    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: tampered,
            sd_mk_backup: created.sd_mk_backup.clone(),
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );
}

#[test]
fn sd_restore_local_backup_rejects_tampered_sd_mk_without_partial_publication() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let create_ctx = TestCtx::new();
    let created = create_sd_on_first_device(&create_ctx, &seed, &sata, &pota);
    let path = create_ctx.path().to_owned();
    create_ctx.erase().expect("explicit partition reset");

    let ctx = TestCtx::new_with_path(&path);
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);
    let mut tampered = created.sd_mk_backup;
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: created.pok_local_backup,
            sd_mk_backup: tampered,
        },
        TborStatus::AesGcmDecryptTagDoesNotMatch,
    );

    // A failed restore must not partially publish SDMK.
    ctx.expect_fw_reject(
        &sd_scoped_sealing_key_request(session.session_id),
        TborStatus::UnsupportedKeyScope,
    );
}
