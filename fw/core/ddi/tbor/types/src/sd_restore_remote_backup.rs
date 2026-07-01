// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TBOR `SdRestoreRemoteBackup` wire schema.
//!
//! `SdRestoreRemoteBackup` is an in-session command that restores a
//! security domain from a remote backup: it unmasks the caller-supplied
//! remote partition-owner-key backup (`pok_remote_backup`, a masked BKS3)
//! under the named sealing key, re-wraps it under the device-local key,
//! and returns the local backup (`pok_local_backup`) together with the
//! security-domain masking-key backup (`sd_mk_backup`).
//!
//! Inputs:
//!
//! * `session_id` — TOC-carried session id; cross-checked against the
//!   SQE-carried session id by the dispatcher (parity with the other
//!   in-session commands).
//! * `sealing_key_id` — vault id
//!   ([`KeyId`](azihsm_fw_ddi_tbor_api::KeyId), TOC entry type 1) of the
//!   sealing key the `pok_remote_backup` is bound to.
//! * `sender_evidence` — sender side-band attestation evidence
//!   ([`Evidence`](crate::evidence::Evidence) field group).
//! * `policy` — the unified [`PartPolicy`] describing the security domain
//!   being restored.  Length pinned to [`PART_POLICY_LEN`] (484 B).
//! * `pok_remote_backup` — the remote partition-owner-key backup to
//!   restore (a masked BKS3), exactly [`MASKED_SD_LEN`] (180 B).
//! * `sd_mk_backup` — **optional** security-domain masking-key backup
//!   envelope.  An empty field means absent; when present it is exactly
//!   [`LOCAL_MK_BACKUP_LEN`] (164 B).
//!
//! Output:
//!
//! * `pok_local_backup` — the partition-owner-key backup re-wrapped under
//!   the device-local key, exactly [`MASKED_SD_LEN`] (180 B).
//! * `sd_mk_backup` — the security-domain masking-key backup envelope,
//!   exactly [`LOCAL_MK_BACKUP_LEN`] (164 B).

use azihsm_fw_ddi_tbor_api::tbor;

use crate::evidence::*;
pub use crate::part_final::LOCAL_MK_BACKUP_LEN;
pub use crate::policy::PART_POLICY_LEN;
pub use crate::sd_create_remote_backup::MASKED_SD_LEN;

/// TBOR opcode for `SdRestoreRemoteBackup`.
pub const TBOR_OP_SD_RESTORE_REMOTE_BACKUP: u8 = 0x0C;

// `policy` carries the unified `PartPolicy`; the derive needs an integer
// literal on the field, so the length is spelled out as `484` and pinned
// against the canonical value here.
const _: () = assert!(PART_POLICY_LEN == 484);

// `pok_remote_backup` / `pok_local_backup` are masked BKS3 envelopes; the
// derive needs an integer literal on the field, so the length is spelled
// out as `180` and pinned against the canonical value here.
const _: () = assert!(MASKED_SD_LEN == 180);

// `sd_mk_backup` is a `local_mk`-style backup envelope; the derive needs
// an integer literal on the field, so the length is spelled out as `164`
// and pinned against the canonical value here.
const _: () = assert!(LOCAL_MK_BACKUP_LEN == 164);

/// `SdRestoreRemoteBackup` request schema.
#[tbor(opcode = 0x0C)]
pub struct TborSdRestoreRemoteBackupReq<'a> {
    /// Session id this request is bound to.  Typed
    /// [`SessionId`](azihsm_fw_ddi_tbor_api::SessionId); the dispatcher
    /// cross-checks it against the SQE-carried session id.
    #[tbor(session_id)]
    pub session_id: SessionId,

    /// Vault id ([`HsmKeyId`](azihsm_fw_hsm_pal_traits::HsmKeyId)) of the
    /// sealing key the `pok_remote_backup` is bound to.  Carried as a
    /// [`KeyId`](azihsm_fw_ddi_tbor_api::KeyId) (TOC entry type 1).
    #[tbor(key_id)]
    pub sealing_key_id: KeyId,

    /// Sender side-band attestation evidence (manufacturer / owner /
    /// partition-owner certificate chains plus the attestation report).
    /// Spliced in as the [`Evidence`](crate::evidence::Evidence) field
    /// group's four TOC entries.
    #[tbor(include)]
    pub sender_evidence: Evidence<'a>,

    /// Caller-asserted unified [`PartPolicy`] describing the security
    /// domain being restored.  Length pinned to [`PART_POLICY_LEN`]
    /// (484 B).
    ///
    /// [`PartPolicy`]: crate::policy::PartPolicy
    #[tbor(buffer, len = 484)]
    pub policy: &'a [u8],

    /// Remote partition-owner-key backup to restore (a masked BKS3).
    /// Always exactly [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_remote_backup: &'a [u8],

    /// Optional security-domain masking-key backup envelope.  An **empty**
    /// field means absent; when present it is exactly
    /// [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, max_len = 164)]
    pub sd_mk_backup: &'a [u8],
}

/// `SdRestoreRemoteBackup` response schema.
#[tbor(response)]
pub struct TborSdRestoreRemoteBackupResp<'a> {
    /// Partition-owner-key backup re-wrapped under the device-local key.
    /// Always exactly [`MASKED_SD_LEN`] (180 B).
    #[tbor(buffer, len = 180)]
    pub pok_local_backup: &'a [u8],

    /// Security-domain masking-key backup envelope.  Always exactly
    /// [`LOCAL_MK_BACKUP_LEN`] (164 B).
    #[tbor(buffer, len = 164)]
    pub sd_mk_backup: &'a [u8],
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use azihsm_fw_ddi_tbor_api::KeyId;
    use azihsm_fw_ddi_tbor_api::SessionId;

    use super::*;

    #[test]
    fn request_round_trips_fields() {
        let policy = [0u8; PART_POLICY_LEN];
        let pok_remote = [0xABu8; MASKED_SD_LEN];
        let sd_mk = [0xCDu8; LOCAL_MK_BACKUP_LEN];
        let cert = CertDescriptor {
            offset: crate::tbor_int::U16::new(0),
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            offset: crate::tbor_int::U16::new(8),
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 1024];
        let frame = TborSdRestoreRemoteBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .sealing_key_id(KeyId(0x5678))
            .unwrap()
            .sender_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .policy(&policy)
            .unwrap()
            .pok_remote_backup(&pok_remote)
            .unwrap()
            .sd_mk_backup(&sd_mk)
            .unwrap()
            .finish();
        assert_eq!(frame.policy().len(), PART_POLICY_LEN);
        assert_eq!(frame.pok_remote_backup().len(), MASKED_SD_LEN);
        assert_eq!(frame.sd_mk_backup().len(), LOCAL_MK_BACKUP_LEN);
    }

    #[test]
    fn request_accepts_absent_sd_mk_backup() {
        let policy = [0u8; PART_POLICY_LEN];
        let pok_remote = [0xABu8; MASKED_SD_LEN];
        let cert = CertDescriptor {
            offset: crate::tbor_int::U16::new(0),
            length: crate::tbor_int::U16::new(8),
        };
        let report = ReportDescriptor {
            offset: crate::tbor_int::U16::new(8),
            length: crate::tbor_int::U16::new(16),
        };
        let chain = [cert];
        let mut buf = [0u8; 1024];
        let frame = TborSdRestoreRemoteBackupReq::encode(&mut buf)
            .unwrap()
            .session_id(SessionId(7))
            .unwrap()
            .sealing_key_id(KeyId(0x5678))
            .unwrap()
            .sender_evidence(|e| {
                e.mfgr_cert_chain(&chain)?
                    .owner_cert_chain(&chain)?
                    .part_owner_cert_chain(&chain)?
                    .evidence(&report)
            })
            .unwrap()
            .policy(&policy)
            .unwrap()
            .pok_remote_backup(&pok_remote)
            .unwrap()
            .sd_mk_backup(&[])
            .unwrap()
            .finish();
        assert!(frame.sd_mk_backup().is_empty());
    }

    #[test]
    fn response_round_trips_backups() {
        let pok_local = [0xABu8; MASKED_SD_LEN];
        let sd_mk = [0xCDu8; LOCAL_MK_BACKUP_LEN];
        let mut buf = [0u8; 512];
        let frame = TborSdRestoreRemoteBackupResp::encode(&mut buf, 0, true)
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
