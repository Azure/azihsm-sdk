// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the TBOR `SdRestoreLocalBackup` command.
//!
//! `SdRestoreLocalBackup` restores a security domain from its device-local
//! backups (`pok_local_backup` = BKS3 masked under `PartLocalMK`,
//! `sd_mk_backup` = SDMK masked under the derived SDBMK), re-masks both at
//! the current SVN, and re-provisions the SD -- the local-reboot recovery
//! path. It needs no sender, HPKE, evidence, or out-of-band data.
//!
//! The command is mainline-supported on both `emu` and hardware, so every
//! test here runs on both backends. Cross-test isolation comes from
//! [`TestCtx::new`](crate::harness::TestCtx::new), which factory-resets the
//! device and holds the process-global lock for the ctx's lifetime, so each
//! test starts from a pristine `Enabled` partition.
//!
//! Recovery spans two devices: a first device finalizes and runs
//! `CreateSD` (capturing the local backups and `PartFinal`'s
//! `local_mk_backup`), then a second device -- factory-reset, same
//! machine seed -- restores `PartLocalMK` via `PartFinal` and finally
//! restores the security domain. The helpers here own that sequence so
//! each submodule expresses only what it is testing.
//!
//! Submodules group tests by what is being exercised:
//! * [`success_path`] -- the full create -> reboot -> restore round trip,
//!   and chaining a second cycle from the refreshed backup pair.
//! * [`fw_rejects`] -- gates that reject before any crypto runs: the
//!   lifecycle gate (not finalized) and the Crypto-Officer role gate.
//! * [`one_shot`] -- the write-once claim: a second restore is refused, a
//!   delivered response cannot be replayed, concurrent callers produce a
//!   single winner, and a *rejected* attempt must not consume the claim.
//! * [`crypto_rejects`] -- envelope failures: a tampered blob, a backup
//!   minted under a different `PartLocalMK`, and a malformed envelope.

use azihsm_ddi_tbor_types::TborPartInfoReq;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

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

mod crypto_rejects;
mod fw_rejects;
mod one_shot;
mod success_path;

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
/// `CreateSD`, and capture everything device 2 needs to recover.
///
/// The `pota` / `sata` trust anchors and machine `seed` come from the
/// caller so device 2 can re-finalize with an identical policy and
/// certificate chain.
fn create_sd_on_first_device(seed: &[u8], sata: &CaKey, pota: &CaKey) -> CreatedSd {
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
        .part_init(&session, seed, &policy, &pota_thumbprint())
        .expect("PartInit");
    let chain = make_pta_chain(pota, &pta_pub_from_csr(&init.pta_csr));
    let local_mk_backup = ctx
        .part_final(&session, &policy, &[], &chain.der_items())
        .expect("PartFinal")
        .local_mk_backup;

    let (masked, report) = masked_key_and_report(&ctx, session.session_id);
    let evidence = build_receiver_evidence(&pid_pub, sata, &report);
    let req = backup_request(session.session_id, masked, &evidence, &policy);
    let resp = ctx
        .tbor_oob(&req, &evidence.oob())
        .expect("SdCreateRemoteBackup");

    CreatedSd {
        policy,
        local_mk_backup,
        pok_local_backup: resp.pok_local_backup.to_vec(),
        sd_mk_backup: resp.sd_mk_backup.to_vec(),
    }
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

/// Run one full recovery cycle on a factory-reset device: restore
/// `PartLocalMK` from `created`, then restore the security domain from
/// the supplied backup pair, returning the **refreshed** pair.
///
/// Owning the `TestCtx` here scopes each cycle's device state -- and the
/// process-global test lock -- to the cycle, so a caller can chain
/// several without holding a stale handle across a factory reset.
fn restore_cycle(
    seed: &[u8],
    pota: &CaKey,
    created: &CreatedSd,
    pok_local_backup: &[u8],
    sd_mk_backup: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, seed, pota, created);
    let resp = ctx
        .tbor(&TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: pok_local_backup.to_vec(),
            sd_mk_backup: sd_mk_backup.to_vec(),
        })
        .expect("SdRestoreLocalBackup cycle");
    (resp.pok_local_backup.clone(), resp.sd_mk_backup.clone())
}

/// Assert the shape every refreshed backup pair must have: exact pinned
/// widths and non-zero content.
fn assert_refreshed_pair(pok_local_backup: &[u8], sd_mk_backup: &[u8]) {
    // Refreshed local backup (BKS3 re-masked under PartLocalMK), 276 B.
    assert_eq!(pok_local_backup.len(), MASKED_SD_LEN);
    assert!(
        pok_local_backup.iter().any(|&b| b != 0),
        "refreshed pok_local_backup must not be all-zero",
    );
    // Refreshed masking-key backup (SDMK re-masked under SDBMK), 260 B.
    assert_eq!(sd_mk_backup.len(), SD_MK_BACKUP_LEN);
    assert!(
        sd_mk_backup.iter().any(|&b| b != 0),
        "refreshed sd_mk_backup must not be all-zero",
    );
}
