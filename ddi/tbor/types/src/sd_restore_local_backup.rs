// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdRestoreLocalBackup` command.
//!
//! `SdRestoreLocalBackup` is an **in-session** command that restores a security
//! domain from its device-local backups: it takes the local
//! partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`), and returns the
//! refreshed local backups of the same.
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_restore_local_backup`; this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::tbor;

/// TBOR opcode for `SdRestoreLocalBackup`.
pub const TBOR_OP_SD_RESTORE_LOCAL_BACKUP: u8 = 0x0D;

/// Host-facing TBOR `SdRestoreLocalBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESTORE_LOCAL_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdRestoreLocalBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Local partition-owner-key backup to restore (a masked BKS3 wrapped
    /// under the device-local key).  Exactly 180 B on the wire; the
    /// firmware schema is the length authority.
    #[tbor(max_len = 180)]
    pub pok_local_backup: Vec<u8>,

    /// Security-domain masking-key backup envelope.  Exactly 164 B on the
    /// wire; the firmware schema is the length authority.
    #[tbor(max_len = 164)]
    pub sd_mk_backup: Vec<u8>,
}

/// Host-facing TBOR `SdRestoreLocalBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdRestoreLocalBackupResp {
    /// Refreshed local partition-owner-key backup (exactly 180 B on the
    /// wire; the firmware schema is the length authority).
    #[tbor(max_len = 180)]
    pub pok_local_backup: Vec<u8>,

    /// Refreshed security-domain masking-key backup envelope (exactly
    /// 164 B on the wire; the firmware schema is the length authority).
    #[tbor(max_len = 164)]
    pub sd_mk_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    const POK_LOCAL_BACKUP_LEN: usize = 180;
    const SD_MK_BACKUP_LEN: usize = 164;

    #[test]
    fn request_encodes_backups() {
        let req = TborSdRestoreLocalBackupReq {
            session_id: 9,
            pok_local_backup: alloc::vec![0xABu8; POK_LOCAL_BACKUP_LEN],
            sd_mk_backup: alloc::vec![0xCDu8; SD_MK_BACKUP_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The two backup blobs must be carried in the data section.
        assert!(
            frame.len() > POK_LOCAL_BACKUP_LEN + SD_MK_BACKUP_LEN,
            "encoded frame must carry both backups"
        );
    }
}
