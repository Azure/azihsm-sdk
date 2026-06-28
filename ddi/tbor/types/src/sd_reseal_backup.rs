// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdResealBackup` command.
//!
//! `SdResealBackup` is an **in-session** command that re-masks an
//! existing security-domain blob (`pok_remote_backup`) for a new recipient: it
//! unmasks the caller-supplied `pok_remote_backup` under the named sealing key
//! and re-masks it under the destination, returning a freshly resealed
//! `pok_remote_backup`.
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_reseal_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.  The source / destination attestation `Evidence`
//! TOC entries are carried by the firmware schema and are not modelled
//! by this host value wrapper.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::policy::PartPolicy;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdResealBackup`.
pub const TBOR_OP_SD_RESEAL_BACKUP: u8 = 0x0B;

/// Host-facing TBOR `SdResealBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESEAL_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdResealBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Vault id (`HsmKeyId`) of the sealing key the source `pok_remote_backup` is
    /// bound to.  Carried as a `KeyId` (inline 16-bit, TOC entry type 1);
    /// represented here as the raw `u16` handle.
    #[tbor(key_id)]
    pub sealing_key_handle: u16,

    /// Unified [`PartPolicy`] describing the security domain being
    /// resealed.  Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,

    /// Source manufacturer certificate-chain descriptors.  Flattened from
    /// the firmware `src_evidence` field group (its four TOC entries); the
    /// DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub src_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Source owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub src_owner_cert_chain: Vec<CertDescriptor>,

    /// Source partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub src_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Source attestation-report (COSE_Sign1) descriptor.
    pub src_report: ReportDescriptor,

    /// Destination manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `dest_evidence` field group (its four TOC
    /// entries).
    #[tbor(max_len = 8)]
    pub dest_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Destination owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dest_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dest_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination attestation-report (COSE_Sign1) descriptor.
    pub dest_report: ReportDescriptor,

    /// Source masked security-domain blob to reseal (exactly
    /// [`MASKED_SD_LEN`](crate::sd_create_remote_backup::MASKED_SD_LEN) =
    /// 180 B on the wire; the firmware schema is the length authority).
    #[tbor(max_len = 180)]
    pub pok_remote_backup: Vec<u8>,
}

/// Host-facing TBOR `SdResealBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdResealBackupResp {
    /// Resealed masked security-domain blob (exactly
    /// [`MASKED_SD_LEN`](crate::sd_create_remote_backup::MASKED_SD_LEN) =
    /// 180 B on the wire; the firmware schema is the length authority).
    pub pok_remote_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;
    use crate::sd_create_remote_backup::MASKED_SD_LEN;

    #[test]
    fn request_encodes_session_policy_and_pok_remote_backup() {
        let req = TborSdResealBackupReq {
            session_id: 9,
            sealing_key_handle: 0x1234,
            policy: PartPolicy::zeroed(),
            pok_remote_backup: alloc::vec![0xABu8; MASKED_SD_LEN],
            ..Default::default()
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy image plus the 180-byte pok_remote_backup must be
        // carried in the data section.
        assert!(
            frame.len() > 484 + MASKED_SD_LEN,
            "encoded frame must carry the policy and pok_remote_backup"
        );
    }
}
