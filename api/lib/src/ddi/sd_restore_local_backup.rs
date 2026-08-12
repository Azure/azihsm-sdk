// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreLocalBackup` (opcode `0x0D`) over the TBOR transport at the DDI
//! layer.
//!
//! Restores a security domain from its device-local backups: takes the
//! local partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`), re-masks both at the
//! current SVN, and returns the refreshed device-local backups. No
//! attestation evidence is involved — the backups are masked under the
//! device-local key, so this command carries no out-of-band data. Runs
//! **inside an already-open session**; the request carries the active
//! session id, which the firmware dispatcher cross-checks against the
//! SQE-carried session id.

use azihsm_ddi_tbor_types::*;

use super::*;

/// Converts the wire `SdRestoreLocalBackup` response into the owned
/// API-layer [`HsmSdRestoreResult`].
impl From<TborSdRestoreLocalBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestoreLocalBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestoreLocalBackup` (opcode `0x0D`) on the active session.
///
/// Restores the security domain from the device-local `pok_local_backup`
/// and `sd_mk_backup`, returning the refreshed device-local backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `pok_local_backup` - The device-local partition-owner-key backup to
///   restore, exactly [`MASKED_SD_LEN`] bytes.
/// * `sd_mk_backup` - The security-domain masking-key backup, exactly
///   [`SD_MK_BACKUP_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `pok_local_backup` or `sd_mk_backup`, and surfaces DDI/device failures
/// from the round-trip.
pub(crate) fn sd_restore_local_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    pok_local_backup: &[u8],
    sd_mk_backup: &[u8],
) -> HsmResult<HsmSdRestoreResult> {
    // The wire fields are `Vec`, but the firmware requires exactly these
    // lengths; enforce them via fixed-size array conversion.
    let pok_local_backup: [u8; MASKED_SD_LEN] = pok_local_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let sd_mk_backup: [u8; SD_MK_BACKUP_LEN] = sd_mk_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;

    let req = TborSdRestoreLocalBackupReq {
        session_id,
        pok_local_backup: pok_local_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.to_vec(),
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, None, &mut cookie)
        .map(HsmSdRestoreResult::from)
        .map_err(HsmError::from)
}
