// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestorePeerBackup` (opcode `0x0F`) at the DDI layer.
//!
//! Restores a security domain from a peer backup: unmasks the
//! caller-supplied peer partition-owner-key backup (`pok_peer_backup`)
//! under the named sealing key, re-wraps it under the device-local
//! key, and returns the local backup (`pok_local_backup`) together
//! with the security-domain masking-key backup (`sd_mk_backup`).
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

impl From<TborSdRestorePeerBackupResp> for SdRestoreResult {
    fn from(resp: TborSdRestorePeerBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestorePeerBackup` (opcode `0x0F`) on the active session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key `pok_peer_backup`
///   is bound to.
/// * `src_evidence` - Source cert-chain / report descriptors.
/// * `part_policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`]
///   bytes) describing the security domain being restored.
/// * `pok_peer_backup` - Peer partition-owner-key backup to restore
///   ([`MASKED_SD_LEN`] bytes).
/// * `sd_mk_backup` - Security-domain masking-key backup envelope
///   ([`SD_MK_BACKUP_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `part_policy`,
/// `pok_peer_backup`, or `sd_mk_backup` have the wrong length, or
/// `part_policy` fails to decode; surfaces DDI/device failures from
/// the round-trip.
pub(crate) fn sd_restore_peer_backup(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    src_evidence: SdEvidence<'_>,
    part_policy: &[u8],
    pok_peer_backup: &[u8],
    sd_mk_backup: &[u8],
) -> HsmResult<SdRestoreResult> {
    if part_policy.len() != PART_POLICY_LEN
        || pok_peer_backup.len() != MASKED_SD_LEN
        || sd_mk_backup.len() != SD_MK_BACKUP_LEN
    {
        return Err(HsmError::InvalidArgument);
    }

    let mut req = TborSdRestorePeerBackupReq {
        session_id,
        sealing_key_id,
        src_mfgr_cert_chain: src_evidence.mfgr_cert_chain.to_vec(),
        src_owner_cert_chain: src_evidence.owner_cert_chain.to_vec(),
        src_part_owner_cert_chain: src_evidence.part_owner_cert_chain.to_vec(),
        src_report: src_evidence.report,
        pok_peer_backup: pok_peer_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.to_vec(),
        ..Default::default()
    };
    req.policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| HsmError::InvalidArgument)?;

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(SdRestoreResult::from)
        .map_err(HsmError::from)
}
