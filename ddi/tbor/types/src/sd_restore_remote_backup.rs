// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdRestoreRemoteBackup` command.
//!
//! `SdRestoreRemoteBackup` is an **in-session** command that
//! restores a security domain from a remote backup: it unmasks the
//! caller-supplied remote partition-owner-key backup
//! (`pok_remote_backup`, a masked BKS3) under the named sealing key,
//! re-wraps it under the device-local key, and returns the local backup
//! (`pok_local_backup`) together with the security-domain masking-key
//! backup (`sd_mk_backup`).
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_restore_remote_backup`; this module
//! adds the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::policy::PartPolicy;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdRestoreRemoteBackup`.
pub const TBOR_OP_SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

/// Host-facing TBOR `SdRestoreRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESTORE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdRestoreRemoteBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Vault id (`HsmKeyId`) of the sealing key the `pok_remote_backup` is
    /// bound to.  Carried as a `KeyId` (inline 16-bit, TOC entry type 1);
    /// represented here as the raw `u16` handle.
    #[tbor(key_id)]
    pub sealing_key_id: u16,

    /// Sender manufacturer certificate-chain descriptors.  Flattened from
    /// the firmware `sender_evidence` field group (its four TOC entries);
    /// the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub sender_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Sender owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub sender_owner_cert_chain: Vec<CertDescriptor>,

    /// Sender partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub sender_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Sender attestation-report (COSE_Sign1) descriptor.
    pub sender_report: ReportDescriptor,

    /// Unified [`PartPolicy`] describing the security domain being
    /// restored.  Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,

    /// Remote partition-owner-key backup to restore (a masked BKS3).
    /// Exactly 180 B on the wire; the firmware schema is the length
    /// authority.
    #[tbor(max_len = 180)]
    pub pok_remote_backup: Vec<u8>,

    /// Optional security-domain masking-key backup envelope.  Empty when
    /// absent; when present it is exactly 164 B on the wire (the firmware
    /// schema is the length authority).
    #[tbor(max_len = 164)]
    pub sd_mk_backup: Vec<u8>,
}

/// Host-facing TBOR `SdRestoreRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdRestoreRemoteBackupResp {
    /// Partition-owner-key backup re-wrapped under the device-local key
    /// (exactly 180 B on the wire; the firmware schema is the length
    /// authority).
    #[tbor(max_len = 180)]
    pub pok_local_backup: Vec<u8>,

    /// Security-domain masking-key backup envelope (exactly 164 B on the
    /// wire; the firmware schema is the length authority).
    #[tbor(max_len = 164)]
    pub sd_mk_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::sd_create_remote_backup::MASKED_SD_LEN;

    const SD_MK_BACKUP_LEN: usize = 164;

    #[test]
    fn request_encodes_all_fields() {
        let req = TborSdRestoreRemoteBackupReq {
            session_id: 9,
            sealing_key_id: 0x1234,
            policy: PartPolicy::zeroed(),
            pok_remote_backup: alloc::vec![0xABu8; MASKED_SD_LEN],
            sd_mk_backup: alloc::vec![0xCDu8; SD_MK_BACKUP_LEN],
            ..Default::default()
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy plus the two backup blobs must be carried in
        // the data section.
        assert!(
            frame.len() > 484 + MASKED_SD_LEN + SD_MK_BACKUP_LEN,
            "encoded frame must carry the policy and backups"
        );
    }

    #[test]
    fn request_encodes_absent_sd_mk_backup() {
        let req = TborSdRestoreRemoteBackupReq {
            session_id: 9,
            sealing_key_id: 0x1234,
            policy: PartPolicy::zeroed(),
            pok_remote_backup: alloc::vec![0xABu8; MASKED_SD_LEN],
            sd_mk_backup: Vec::new(),
            ..Default::default()
        };

        let mut buf = [0u8; 1024];
        req.encode_request(&mut buf).expect("encode");
    }
}
