// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdResealRemoteBackup` command.
//!
//! `SdResealRemoteBackup` is an **in-session** command run by a Sealing
//! Authority that **reseals** a remote security-domain backup from a source
//! recipient to a destination recipient: it HPKE-unseals the caller-supplied
//! `src_remote_backup` with the masked receiver key (recovering the BKS3)
//! and HPKE-reseals that BKS3 to the destination receiver, returning
//! `dst_remote_backup`.
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_reseal_remote_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.  The source / destination attestation `Evidence`
//! TOC entries are carried by the firmware schema and are not modelled
//! by this host value wrapper.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::policy::PartPolicy;
use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdResealRemoteBackup`.
pub const TBOR_OP_SD_RESEAL_REMOTE_BACKUP: u8 = 0x0B;

/// Host-facing TBOR `SdResealRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_RESEAL_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdResealRemoteBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The masked SD-sealing key (from `SdSealingKeyGen`), exactly
    /// [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover
    /// the receiver's private HPKE key; a fixed-length `[u8; N]` field
    /// (mirrors the firmware `len = 180`), never a vault handle.
    pub masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],

    /// Unified [`PartPolicy`] the source and destination must share.
    /// Encoded as its 484-byte little-endian image.
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

    /// Source remote backup to reseal: an HPKE-Auth seal, exactly
    /// [`POK_REMOTE_BACKUP_LEN`] (161 B).  A fixed-length `[u8; N]` field
    /// (the host derive's exact-length form; the firmware schema is the
    /// length authority).
    pub src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],
}

/// Host-facing TBOR `SdResealRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSdResealRemoteBackupResp {
    /// Resealed remote backup: an HPKE-Auth seal of the same BKS3 to the
    /// destination receiver, exactly [`POK_REMOTE_BACKUP_LEN`] (161 B).  A
    /// fixed-length `[u8; N]` field so host decode enforces the exact
    /// length — the firmware schema is the length authority.
    pub dst_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_policy_and_src_remote_backup() {
        let req = TborSdResealRemoteBackupReq {
            session_id: 9,
            masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
            policy: PartPolicy::zeroed(),
            src_mfgr_cert_chain: Vec::new(),
            src_owner_cert_chain: Vec::new(),
            src_part_owner_cert_chain: Vec::new(),
            src_report: ReportDescriptor::default(),
            dest_mfgr_cert_chain: Vec::new(),
            dest_owner_cert_chain: Vec::new(),
            dest_part_owner_cert_chain: Vec::new(),
            dest_report: ReportDescriptor::default(),
            src_remote_backup: [0xABu8; POK_REMOTE_BACKUP_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy image plus the 161-byte src_remote_backup must
        // be carried in the data section.
        assert!(
            frame.len() > 484 + POK_REMOTE_BACKUP_LEN,
            "encoded frame must carry the policy and src_remote_backup"
        );
    }
}
