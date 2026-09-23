// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` success paths: the create -> reboot -> restore
//! round trip, and chaining a second cycle from the refreshed pair.

use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use super::assert_refreshed_pair;
use super::create_sd_on_first_device;
use super::reboot_and_restore_part_local_mk;
use super::restore_cycle;
use crate::commands::part_init::mach_seed;
use crate::harness::x509_fixture::CaKey;
use crate::harness::TestCtx;

/// The realistic recovery sequence: device 1 creates the SD, device 2
/// reboots, restores `PartLocalMK`, and restores the security domain from
/// the captured backups. The response must carry a well-formed refreshed
/// pair.
#[test]
fn sd_restore_local_backup_roundtrip() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    let ctx = TestCtx::new();
    let session = reboot_and_restore_part_local_mk(&ctx, &seed, &pota, &created);

    let resp = ctx
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
}

/// Restore twice, the second cycle consuming the first cycle's output.
///
/// Opening a refreshed pair proves it is semantically valid, not merely
/// well-formed: a restore that stamped the wrong key kind, usage flags,
/// label or scope would still return two non-zero buffers of the right
/// width, and is only caught when a later restore has to open them.
#[test]
fn sd_restore_local_backup_chained_restore() {
    let seed = mach_seed();
    let sata = CaKey::generate();
    let pota = CaKey::generate();

    let created = create_sd_on_first_device(&seed, &sata, &pota);

    // Cycle 1 consumes `CreateSD`'s backups and mints a refreshed pair.
    let (pok_2, sd_mk_2) = restore_cycle(
        &seed,
        &pota,
        &created,
        &created.pok_local_backup,
        &created.sd_mk_backup,
    );
    assert_refreshed_pair(&pok_2, &sd_mk_2);

    // Cycle 2 consumes cycle 1's output.
    let (pok_3, sd_mk_3) = restore_cycle(&seed, &pota, &created, &pok_2, &sd_mk_2);
    assert_refreshed_pair(&pok_3, &sd_mk_3);

    // Each cycle re-masks under a fresh AEAD IV, so consecutive envelopes
    // must differ even though they carry the same key material.
    assert_ne!(
        pok_2, pok_3,
        "each cycle must mint a distinct pok_local_backup envelope",
    );
    assert_ne!(
        sd_mk_2, sd_mk_3,
        "each cycle must mint a distinct sd_mk_backup envelope",
    );
}
