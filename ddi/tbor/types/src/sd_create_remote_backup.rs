// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side wrapper for the TBOR `SdCreateRemoteBackup` command.
//!
//! `SdCreateRemoteBackup` is an **in-session Crypto Officer** command
//! that creates a new security domain under the active session's
//! partition from the caller-supplied unified `PartPolicy`, returning
//! the remote partition-owner-key backup (`pok_remote_backup`) together
//! with the local partition-owner-key backup (`pok_local_backup`) and the
//! security-domain masking-key backup (`sd_mk_backup`).
//!
//! Both wire schemas are shared with the firmware handler via
//! `azihsm_fw_ddi_tbor_types::sd_create_remote_backup`; this module adds
//! the host-facing value types so [`exec_op_tbor`] returns owned
//! response values.
//!
//! [`exec_op_tbor`]: ../../azihsm_ddi_interface/trait.DdiDev.html#method.exec_op_tbor

use alloc::vec::Vec;

use crate::evidence::ReportDescriptor;
use crate::policy::PartPolicy;
use crate::sd_sealing_key_gen::MASKED_SEALING_KEY_LEN;
use crate::tbor;
use crate::CertDescriptor;

/// TBOR opcode for `SdCreateRemoteBackup`.
pub const TBOR_OP_SD_CREATE_REMOTE_BACKUP: u8 = 0x0A;

/// Exact on-the-wire length of a **masked** security-domain blob (a
/// masked BKS3).  Retained as the shared length authority for the rest
/// of the Security-Domain backup family (`SdReseal`, `SdRestore*`), which
/// re-export it; **this** command's response is an HPKE-Auth seal sized
/// by [`POK_REMOTE_BACKUP_LEN`].
pub const MASKED_SD_LEN: usize = 180;

/// Exact on-the-wire length of the remote partition-owner-key backup (an
/// HPKE-Auth seal of BKS3: `enc(97) ‖ ct(64)`).  Mirrors
/// `azihsm_fw_ddi_tbor_types::sd_create_remote_backup::
/// POK_REMOTE_BACKUP_LEN`; the firmware schema is the length authority.
pub const POK_REMOTE_BACKUP_LEN: usize = 161;

/// Exact on-the-wire length of the security-domain masking-key backup
/// envelope (`SDMK` masked under `SDBMK`).  Mirrors the firmware
/// `LOCAL_MK_BACKUP_LEN`; the firmware schema is the length authority.
pub const SD_MK_BACKUP_LEN: usize = 164;

/// Host-facing TBOR `SdCreateRemoteBackup` request.
#[tbor(opcode = TBOR_OP_SD_CREATE_REMOTE_BACKUP, session_ctrl = in_session)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupReq {
    /// CO session id this request is bound to.  Cross-checked against the
    /// SQE-carried session id by the dispatcher.
    #[tbor(session_id)]
    pub session_id: u16,

    /// The sender's masked SD-sealing key (from `SdSealingKeyGen`),
    /// exactly [`MASKED_SEALING_KEY_LEN`] (180 B).  Unmasked on-device to
    /// recover the sender's private ECDH key.  A fixed-length `[u8; N]`
    /// field (a `min_len == max_len` buffer): the array type is the host
    /// derive's exact-length form, mirroring the firmware `len = 180`.
    pub masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN],

    /// Receiver manufacturer certificate-chain descriptors.  Flattened
    /// from the firmware `receiver_evidence` field group (first of its
    /// four TOC entries); the DER bytes travel out of band.
    #[tbor(max_len = 8)]
    pub receiver_mfgr_cert_chain: Vec<CertDescriptor>,

    /// Receiver owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub receiver_owner_cert_chain: Vec<CertDescriptor>,

    /// Receiver partition-owner certificate-chain descriptors.
    #[tbor(max_len = 8)]
    pub receiver_part_owner_cert_chain: Vec<CertDescriptor>,

    /// Receiver attestation-report (COSE_Sign1) descriptor.
    pub receiver_report: ReportDescriptor,

    /// Unified [`PartPolicy`] describing the security domain to create.
    /// Encoded as its 484-byte little-endian image.
    pub policy: PartPolicy,
}

/// Host-facing TBOR `SdCreateRemoteBackup` response.
#[tbor(response)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TborSdCreateRemoteBackupResp {
    /// Remote partition-owner-key backup: an HPKE-Auth seal of BKS3
    /// (exactly [`POK_REMOTE_BACKUP_LEN`] = 161 B on the wire; the
    /// firmware schema is the length authority).  A fixed-length `[u8; N]`
    /// field so host decode enforces the exact length — rejecting any
    /// malformed frame — instead of allocating from the encoded length.
    pub pok_remote_backup: [u8; POK_REMOTE_BACKUP_LEN],

    /// Local partition-owner-key backup: the fresh BKS3 masked under the
    /// partition-local masking key (exactly [`MASKED_SD_LEN`] = 180 B on
    /// the wire).  Persisted by the host and replayed to recover the
    /// security domain locally.
    pub pok_local_backup: [u8; MASKED_SD_LEN],

    /// Security-domain masking-key backup: the freshly minted `SDMK`
    /// masked under the derived `SDBMK` (exactly [`SD_MK_BACKUP_LEN`] =
    /// 164 B on the wire).  Persisted by the host and replayed on restore.
    pub sd_mk_backup: [u8; SD_MK_BACKUP_LEN],
}

#[cfg(test)]
mod tests {
    use azihsm_ddi_tbor_types::TborOpReq;

    use super::*;

    #[test]
    fn request_encodes_session_and_policy() {
        let req = TborSdCreateRemoteBackupReq {
            session_id: 9,
            masked_sealing_key: [0u8; MASKED_SEALING_KEY_LEN],
            receiver_mfgr_cert_chain: Vec::new(),
            receiver_owner_cert_chain: Vec::new(),
            receiver_part_owner_cert_chain: Vec::new(),
            receiver_report: ReportDescriptor::default(),
            policy: PartPolicy::zeroed(),
        };

        let mut buf = [0u8; 1024];
        let frame = req.encode_request(&mut buf).expect("encode");

        // The 484-byte policy image must be carried in the data section.
        assert!(frame.len() > 484, "encoded frame must carry the policy");
    }
}
