// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdRestoreRemoteBackup` command.
//!
//! `SdRestoreRemoteBackup` is an **in-session** command that restores a
//! security domain from a **remote** backup (manticore §3.3.8): it
//! HPKE-Auth-opens the caller-supplied `src_remote_backup` (an HPKE seal of
//! BKS3) with the masked receiver key — authenticated by the sender's
//! attested key — recovers `SDMK` from `prev_sd_mk_backup`, and returns the
//! device-local backups (`pok_local_backup`, `sd_mk_backup`).
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
use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
use crate::sd_create_remote_backup::SD_MK_BACKUP_LEN;
use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdRestoreRemoteBackup`.
pub const TBOR_OP_SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

/// Host-facing TBOR `SdRestoreRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESTORE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdRestoreRemoteBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The receiver's masked SD-sealing key (from `SdSealingKeyGen`),
    /// exactly [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to
    /// recover the receiver's private HPKE key (`RcvrPriv`).
    pub masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],

    /// Unified [`PartPolicy`] describing the security domain being
    /// restored.  Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,

    /// Sender manufacturer certificate-chain descriptors.  Flattened from
    /// the firmware `sender_evidence` field group (first of its four TOC
    /// entries); the DER bytes travel out of band.
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

    /// Remote backup to restore: an HPKE-Auth seal of BKS3, exactly
    /// [`POK_REMOTE_BACKUP_LEN`] (161 B).  The firmware schema is the length
    /// authority.
    pub src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],

    /// Previous security-domain masking-key backup (SDMK masked under the
    /// derived SDBMK), exactly [`SD_MK_BACKUP_LEN`] (164 B), from which
    /// `SDMK` is recovered.
    pub prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
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

    #[test]
    fn request_encodes_all_fields() {
        let req = TborSdRestoreRemoteBackupReq {
            session_id: 9,
            masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
            policy: PartPolicy::zeroed(),
            sender_mfgr_cert_chain: Vec::new(),
            sender_owner_cert_chain: Vec::new(),
            sender_part_owner_cert_chain: Vec::new(),
            sender_report: ReportDescriptor::default(),
            src_remote_backup: [0xABu8; POK_REMOTE_BACKUP_LEN],
            prev_sd_mk_backup: [0xCDu8; SD_MK_BACKUP_LEN],
        };

        let mut buf = [0u8; 2048];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy plus the sealing key and the two backups must
        // be carried in the data section.
        assert!(
            frame.len() > 484 + MASKED_SEALING_KEY_LEN + POK_REMOTE_BACKUP_LEN + SD_MK_BACKUP_LEN,
            "encoded frame must carry the policy, key, and backups"
        );
    }
}
