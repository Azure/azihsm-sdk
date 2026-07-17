// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreatePeerBackup` command.
//!
//! `SdCreatePeerBackup` is an **in-session** command that creates a
//! peer-transferable backup of a security domain (manticore §3.3.10): it
//! recovers BKS3 from the caller's device-local backup (`pok_local_backup`)
//! and HPKE-Auth-seals it to the destination peer named by `dst_evidence` —
//! authenticated by the sender's own masked SD-sealing key — returning the
//! peer backup (`pok_peer_backup`).  Peer cloning is gated by the security
//! domain's `allow_peer_cloning` policy flag.
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
use crate::sd_create_remote_backup::MASKED_SD_LEN;
use crate::sd_create_remote_backup::POK_REMOTE_BACKUP_LEN;
use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdCreatePeerBackup`.
pub const TBOR_OP_SD_CREATE_PEER_BACKUP: u8 = 0x0E;

/// Host-facing TBOR `SdCreatePeerBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_PEER_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupReq {
    /// Session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The sender's masked SD-sealing key (from `SdSealingKeyGen`), exactly
    /// [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to recover
    /// the sender's private HPKE key (`SndrPriv`) that authenticates the
    /// seal.  A fixed-length `[u8; N]` field; the firmware schema is the
    /// length authority.
    pub masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],

    /// Unified [`PartPolicy`] describing the security domain being backed
    /// up.  Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,

    /// Destination manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `dst_evidence` field group (first of its four TOC
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

    /// Device-local partition-owner-key backup (a masked BKS3 wrapped under
    /// `PartLocalMK`) from which BKS3 is recovered.  Exactly
    /// [`MASKED_SD_LEN`] (180 B); the firmware schema is the length
    /// authority.
    pub pok_local_backup: [u8; MASKED_SD_LEN],
}

/// Host-facing TBOR `SdCreatePeerBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSdCreatePeerBackupResp {
    /// Peer backup: an HPKE-Auth seal of BKS3 (exactly
    /// [`POK_REMOTE_BACKUP_LEN`] = 161 B on the wire; the firmware schema is
    /// the length authority).  A fixed-length `[u8; N]` field.
    pub pok_peer_backup: [u8; POK_REMOTE_BACKUP_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_fields() {
        let req = TborSdCreatePeerBackupReq {
            session_id: 9,
            masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
            policy: PartPolicy::zeroed(),
            dst_mfgr_cert_chain: Vec::new(),
            dst_owner_cert_chain: Vec::new(),
            dst_part_owner_cert_chain: Vec::new(),
            dst_report: ReportDescriptor::default(),
            pok_local_backup: [0xABu8; MASKED_SD_LEN],
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy plus the sealing key and the backup must be
        // carried in the data section.
        assert!(
            frame.len() > 484 + MASKED_SEALING_KEY_LEN + MASKED_SD_LEN,
            "encoded frame must carry the policy, key, and backup"
        );
    }
}
