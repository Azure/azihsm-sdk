// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreRemoteBackup` (opcode `0x0C`) at the DDI layer.
//!
//! Restores a security domain from a remote backup: unmasks the
//! caller-supplied remote partition-owner-key backup
//! (`pok_remote_backup`) under the named sealing key, re-wraps it
//! under the device-local key, and returns the local backup
//! (`pok_local_backup`) together with the security-domain masking-key
//! backup (`sd_mk_backup`).
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

impl From<TborSdRestoreRemoteBackupResp> for SdRestoreResult {
    fn from(resp: TborSdRestoreRemoteBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestoreRemoteBackup` (opcode `0x0C`) on the active session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key `pok_remote_backup`
///   is bound to.
/// * `sender_evidence` - Sender cert-chain / report descriptors.
/// * `part_policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`]
///   bytes) describing the security domain being restored.
/// * `pok_remote_backup` - Remote partition-owner-key backup to
///   restore ([`MASKED_SD_LEN`] bytes).
/// * `sd_mk_backup` - Optional security-domain masking-key backup
///   envelope ([`SD_MK_BACKUP_LEN`] bytes); `None` when absent.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `part_policy` or
/// `pok_remote_backup` have the wrong length, `part_policy` fails to
/// decode, or `sd_mk_backup` is present with the wrong length;
/// surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_restore_remote_backup(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    sender_evidence: SdEvidence<'_>,
    part_policy: &[u8],
    pok_remote_backup: &[u8],
    sd_mk_backup: Option<&[u8]>,
) -> HsmResult<SdRestoreResult> {
    if part_policy.len() != PART_POLICY_LEN || pok_remote_backup.len() != MASKED_SD_LEN {
        return Err(HsmError::InvalidArgument);
    }
    if sd_mk_backup.is_some_and(|b| b.len() != SD_MK_BACKUP_LEN) {
        return Err(HsmError::InvalidArgument);
    }

    let mut req = TborSdRestoreRemoteBackupReq {
        session_id,
        sealing_key_id,
        sender_mfgr_cert_chain: sender_evidence.mfgr_cert_chain.to_vec(),
        sender_owner_cert_chain: sender_evidence.owner_cert_chain.to_vec(),
        sender_part_owner_cert_chain: sender_evidence.part_owner_cert_chain.to_vec(),
        sender_report: sender_evidence.report,
        pok_remote_backup: pok_remote_backup.to_vec(),
        ..Default::default()
    };
    req.policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| HsmError::InvalidArgument)?;
    if let Some(b) = sd_mk_backup {
        req.sd_mk_backup = b.to_vec();
    }

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(SdRestoreResult::from)
        .map_err(HsmError::from)
}
