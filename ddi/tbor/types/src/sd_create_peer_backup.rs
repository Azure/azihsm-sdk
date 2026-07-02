// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreatePeerBackup` command.
//!
//! `SdCreatePeerBackup` is an **in-session** command that creates a
//! peer-transferable backup of a security domain: it takes the local
//! partition-owner-key backup (`pok_local_backup`), re-masks it for the
//! destination peer named by `dst_evidence` under the named sealing key,
//! and returns the peer backup (`pok_peer_backup`).
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_create_peer_backup`; this module adds the
//! host-facing value types so [`exec_op_tbor`] returns owned response
//! values.  The firmware splices the destination attestation evidence in
//! as an `Evidence` field group; the host derive has no field-group
//! support, so this wrapper spells those four TOC entries out explicitly
//! as the `dst_*` cert-chain / report descriptor fields.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::policy::PartPolicy;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdCreatePeerBackup`.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

/// Host-facing TBOR `SdCreatePeerBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_PEER_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// Vault id (`HsmKeyId`) of the sealing key the `pok_local_backup` is
    /// bound to.  Carried as a `KeyId` (inline 16-bit, TOC entry type 1);
    /// represented here as the raw `u16` handle.
    #[tbor(key_id)]
    pub sealing_key_id: u16,

    /// Destination manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `dst_evidence` field group (its four TOC
    /// entries); the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub dst_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Destination owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dst_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub dst_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Destination attestation-report (COSE_Sign1) descriptor.
    pub dst_report: ReportDescriptor,

    /// Unified [`PartPolicy`] describing the security domain being backed
    /// up.  Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,

    /// Local partition-owner-key backup to re-mask (a masked BKS3 wrapped
    /// under the device-local key).  Exactly 180 B on the wire; the
    /// firmware schema is the length authority.
    #[tbor(max_len = 180)]
    pub pok_local_backup: Vec<u8>,
}

/// Host-facing TBOR `SdCreatePeerBackup` response.
#[tbor(response)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupResp {
    /// Partition-owner-key backup re-masked for the destination peer
    /// (exactly 180 B on the wire; the firmware schema is the length
    /// authority).
    #[tbor(max_len = 180)]
    pub pok_peer_backup: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    const POK_BACKUP_LEN: usize = 180;

    #[test]
    fn request_encodes_fields() {
        let req = TborSdCreatePeerBackupReq {
            session_id: 9,
            sealing_key_id: 0x1234,
            policy: PartPolicy::zeroed(),
            pok_local_backup: alloc::vec![0xABu8; POK_BACKUP_LEN],
            ..Default::default()
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy plus the 180-byte backup must be carried in
        // the data section.
        assert!(
            frame.len() > 484 + POK_BACKUP_LEN,
            "encoded frame must carry the policy and backup"
        );
    }
}
