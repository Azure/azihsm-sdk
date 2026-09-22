// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` gates that reject before any crypto.
//!
//! Both fire in the handler prologue, so neither reaches an unmask: the
//! lifecycle gate (partition not `Initialized`, so there is no
//! `PartLocalMK`) and the Crypto-Officer role gate.

use azihsm_ddi_tbor_types::SessionType;
use azihsm_ddi_tbor_types::TborSdRestoreLocalBackupReq;
use azihsm_ddi_tbor_types::TborStatus;
use azihsm_ddi_tbor_types::MASKED_SD_LEN;
use azihsm_ddi_tbor_types::SD_MK_BACKUP_LEN;

use crate::harness::bootstrap_rotated_co;
use crate::harness::SessionOpenInitOptions;
use crate::harness::TestCtx;
use crate::harness::CU_PSK_ID as CU;
use crate::harness::ROTATED_CO_PSK;
use crate::harness::ROTATED_CU_PSK;

/// A partition that has not been finalized has no `PartLocalMK`, so the
/// lifecycle gate must reject with [`TborStatus::InvalidArg`] before any
/// unmask runs.
#[test]
fn sd_restore_local_backup_rejects_before_finalize() {
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

/// CU session under a rotated PSK: the handler's CO-only role gate must
/// surface [`TborStatus::InvalidPermissions`].
///
/// The role gate runs before the lifecycle and one-shot gates, so no
/// finalized partition is needed. The CU PSK is rotated off its default
/// first, otherwise the dispatcher's default-PSK gate fires ahead of the
/// handler and the test would pass for the wrong reason. CU sessions are
/// pinned to `SessionType::PlainText`; `Authenticated` is CO-only.
#[test]
fn sd_restore_local_backup_rejects_non_co_session() {
    let ctx = TestCtx::new();
    let bootstrap = ctx
        .open_session(CU, SessionType::PlainText)
        .expect("open_session must succeed");
    ctx.psk_change(bootstrap.handshake(), &ROTATED_CU_PSK)
        .expect("rotate CU PSK");
    bootstrap.close().expect("close bootstrap CU session");

    let opts = SessionOpenInitOptions::new(CU, SessionType::PlainText).with_psk(&ROTATED_CU_PSK);
    let pending = ctx
        .session_open_init_with_options(opts)
        .expect("CU session_open_init under rotated PSK");
    let session = ctx
        .session_open_finish(pending)
        .expect("CU session_open_finish under rotated PSK");

    ctx.expect_fw_reject(
        &TborSdRestoreLocalBackupReq {
            session_id: session.session_id,
            pok_local_backup: vec![0u8; MASKED_SD_LEN],
            sd_mk_backup: vec![0u8; SD_MK_BACKUP_LEN],
        },
        TborStatus::InvalidPermissions,
    );
}
