// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreateRemoteBackup` command.
//!
//! `SdCreateRemoteBackup` is an **in-session Crypto Officer** command
//! that creates a new security domain under the active session's
//! partition from the caller-supplied unified `PartPolicy`, returning
//! the remote partition-owner-key backup (`pok_remote_backup`).
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_create_remote_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::policy::PartPolicy;
use crate::tbor;

/// TBOR opcode for `SdCreateRemoteBackup`.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

/// Exact on-the-wire length of the masked security-domain blob (a masked
/// BKS3).  Mirrors
/// `azihsm_fw_ddi_tbor_types::sd_create_remote_backup::MASKED_SD_LEN`; the
/// firmware schema is the length authority.
pub const MASKED_SD_LEN: usize = 180;

/// Host-facing TBOR `SdCreateRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Unified [`PartPolicy`] describing the security domain to create.
    /// Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,
}

/// Host-facing TBOR `SdCreateRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupResp {
    /// Remote partition-owner-key backup, a masked BKS3 (exactly
    /// [`MASKED_SD_LEN`] = 180 B on the wire; the firmware schema is the
    /// length authority).
    pub pok_remote_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_policy() {
        let req = TborSdCreateRemoteBackupReq {
            session_id: 9,
            policy: PartPolicy::zeroed(),
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy image must be carried in the data section.
        assert!(frame.len() > 484, "encoded frame must carry the policy");
    }
}
