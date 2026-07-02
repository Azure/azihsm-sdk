// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` (opcode `0x0D`) at the DDI layer.
//!
//! Restores a security domain from its device-local backups: takes the
//! local partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`), and returns
//! the refreshed local backups of the same.
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

/// Exact on-the-wire length of the security-domain masking-key backup
/// envelope (`sd_mk_backup`). Shared by the `SdRestore*Backup` family.
pub(crate) const SD_MK_BACKUP_LEN: usize = 164;

/// Owned result of a `SdRestore*Backup` round-trip: the refreshed
/// local partition-owner-key backup plus the refreshed security-domain
/// masking-key backup.
///
/// Shared by [`sd_restore_local_backup`],
/// [`super::sd_restore_peer_backup::sd_restore_peer_backup`], and
/// [`super::sd_restore_remote_backup::sd_restore_remote_backup`], whose
/// responses all carry the same two fields.
pub(crate) struct SdRestoreResult {
    pub pok_local_backup: Vec<u8>,
    pub sd_mk_backup: Vec<u8>,
}

impl From<TborSdRestoreLocalBackupResp> for SdRestoreResult {
    fn from(resp: TborSdRestoreLocalBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestoreLocalBackup` (opcode `0x0D`) on the active session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `pok_local_backup` - Local partition-owner-key backup to restore
///   ([`MASKED_SD_LEN`] bytes).
/// * `sd_mk_backup` - Security-domain masking-key backup envelope
///   ([`SD_MK_BACKUP_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `pok_local_backup` or
/// `sd_mk_backup` have the wrong length; surfaces DDI/device failures
/// from the round-trip.
pub(crate) fn sd_restore_local_backup(
    partition: &HsmPartition,
    session_id: u16,
    pok_local_backup: &[u8],
    sd_mk_backup: &[u8],
) -> HsmResult<SdRestoreResult> {
    if pok_local_backup.len() != MASKED_SD_LEN || sd_mk_backup.len() != SD_MK_BACKUP_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let req = TborSdRestoreLocalBackupReq {
        session_id,
        pok_local_backup: pok_local_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.to_vec(),
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(SdRestoreResult::from)
        .map_err(HsmError::from)
}
