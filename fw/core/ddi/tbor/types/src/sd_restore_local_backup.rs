// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdRestoreLocalBackup` wire schema.
//!
//! `SdRestoreLocalBackup` is an in-session command that restores a security
//! domain from its device-local backups: it takes the local
//! partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`), and returns the
//! refreshed local backups of the same.
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `pok_local_backup` — the local partition-owner-key backup to restore
//!   (a masked BKS3 wrapped under the device-local key), exactly
//!   [`MASKED_SD_LEN`] (180 B).
//! * `sd_mk_backup` — the security-domain masking-key backup envelope,
//!   exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).
//!
//! Output:
//!
//! * `pok_local_backup` — the refreshed local partition-owner-key backup,
//!   exactly [`MASKED_SD_LEN`] (180 B).
//! * `sd_mk_backup` — the refreshed security-domain masking-key backup
//!   envelope, exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).

use azihsm_fw_ddi_tbor_api::tbor;

pub use crate::part_final::LOCAL_MK_BACKUP_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;

/// TBOR opcode for `SdRestoreLocalBackup`.
pub const TBOR_OP_SD_RESTORE_LOCAL_BACKUP: u8 = 0x0D;

// `pok_local_backup` is a masked BKS3 envelope; the derive needs an
// integer literal on the field, so the length is spelled out as `180` and
// pinned against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

// `sd_mk_backup` is a `local_mk`-style backup envelope; the derive needs
// an integer literal on the field, so the length is spelled out as `164`
// and pinned against the canonical value here.
const _: () = assert!(LOCAL_MK_BACKUP_LEN == 164);

/// `SdRestoreLocalBackup` request schema.
#[tbor(opcode = 0x0D)]
pub struct TborSdRestoreLocalBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Local partition-owner-key backup to restore (a masked BKS3 wrapped
    /// under the device-local key).  Always exactly [`MASKED_SD_LEN`]
    /// (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],

    /// Security-domain masking-key backup envelope.  Always exactly
    /// [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub sd_mk_backup: &'a [u8],
}

/// `SdRestoreLocalBackup` response schema.
#[tbor(response)]
pub struct TborSdRestoreLocalBackupResp<'a> {
    /// Refreshed local partition-owner-key backup.  Always exactly
    /// [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],

    /// Refreshed security-domain masking-key backup envelope.  Always
    /// exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub sd_mk_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_backups() {
        let pok_local = [0xABu8; MASKED_SD_LEN];
        let sd_mk = [0xCDu8; LOCAL_MK_BACKUP_LEN];
        let mut buf = [0u8; 1024];
        let frame = TborSdRestoreLocalBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .pok_local_backup(&pok_local)
            .unwrap()
            .sd_mk_backup(&sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
        assert_eq!(frame.sd_mk_backup().len(), LOCAL_MK_BACKUP_LEN);
    }

    #[test]
    fn response_round_trips_backups() {
        let pok_local = [0xABu8; MASKED_SD_LEN];
        let sd_mk = [0xCDu8; LOCAL_MK_BACKUP_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdRestoreLocalBackupResp::encode(&mut buf, 0, true)
            .unwrap()
            .pok_local_backup(&pok_local)
            .unwrap()
            .sd_mk_backup(&sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.pok_local_backup().len(), MASKED_SD_LEN);
        assert_eq!(frame.sd_mk_backup().len(), LOCAL_MK_BACKUP_LEN);
    }
}
