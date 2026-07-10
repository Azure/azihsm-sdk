// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Security-domain backup / restore commands over the TBOR transport at
//! the DDI layer.
//!
//! This module hosts the host-side dispatch for the in-session
//! security-domain backup and restore family, mirroring the firmware
//! handlers:
//!
//! * **`SdCreateRemoteBackup`** (opcode `0x0A`) — create a new security
//!   domain from a unified `PartPolicy`, returning the remote
//!   partition-owner-key backup.
//! * **`SdResealBackup`** (opcode `0x0B`) — re-mask an existing remote
//!   backup for a new recipient.
//! * **`SdRestoreRemoteBackup`** (opcode `0x0C`) — restore a security
//!   domain from a remote backup.
//! * **`SdRestoreLocalBackup`** (opcode `0x0D`) — restore a security
//!   domain from its device-local backups (no attestation evidence).
//! * **`SdCreatePeerBackup`** (opcode `0x0E`) — re-mask a local backup
//!   for a destination peer.
//! * **`SdRestorePeerBackup`** (opcode `0x0F`) — restore a security
//!   domain from a peer backup.
//!
//! All commands run **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`]: the request carries the active
//! session id, which the firmware dispatcher cross-checks against the
//! SQE-carried session id.
//!
//! # Out-of-band evidence (not yet transmitted)
//!
//! Five of these commands reference their bulk attestation evidence — DER
//! certificate chains and a COSE_Sign1 report — out of band via
//! `(index, length)` descriptors that point at OOB SGL Data Blocks. The
//! DDI transport ([`azihsm_ddi_interface::DdiDev::exec_op_tbor`]) can now
//! carry those blocks (its `oob_items` parameter), but this SDK layer does
//! not yet populate the descriptors or pass the evidence: the
//! [`HsmSdEvidence`] inputs accepted here are **not yet transmitted** (the
//! descriptor fields are left empty and `None` is passed for `oob_items`).
//! These signatures exist now so the API surface is ready; wiring the
//! evidence through is future work.

use azihsm_ddi_tbor_types::*;

use super::*;

/// Exact on-the-wire length of a masked partition-owner-key backup (a
/// masked BKS3). The firmware schema is the length authority.
const POK_BACKUP_LEN: usize = 180;

/// Exact on-the-wire length of a security-domain masking-key backup
/// envelope. The firmware schema is the length authority.
const SD_MK_BACKUP_LEN: usize = 164;

/// Converts each SD restore wire response into the public
/// [`HsmSdRestoreResult`], keeping the wire response types confined to the
/// DDI layer.
impl From<TborSdRestoreLocalBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestoreLocalBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

impl From<TborSdRestoreRemoteBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestoreRemoteBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

impl From<TborSdRestorePeerBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestorePeerBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Decodes a caller-supplied unified `PartPolicy` image
/// ([`PART_POLICY_LEN`] bytes), failing fast with
/// [`HsmError::InvalidArgument`] on a wrong length or malformed image.
fn decode_policy(policy: &[u8]) -> HsmResult<PartPolicy> {
    if policy.len() != PART_POLICY_LEN {
        return Err(HsmError::InvalidArgument);
    }
    <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(policy)
        .map_err(|_| HsmError::InvalidArgument)
}

/// Validates a fixed-length backup blob, returning
/// [`HsmError::InvalidArgument`] on a length mismatch.
fn check_len(blob: &[u8], expected: usize) -> HsmResult<()> {
    if blob.len() != expected {
        return Err(HsmError::InvalidArgument);
    }
    Ok(())
}

/// Issue `SdCreateRemoteBackup` (opcode `0x0A`) on the active session.
///
/// Creates a new security domain from the caller-supplied unified
/// `policy` and returns the remote partition-owner-key backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sender_key` - Vault id the masked security domain is wrapped under.
/// * `receiver_evidence` - Receiver attestation evidence (**accepted but
///   not yet transmitted**; see module docs).
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy`, and
/// surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_create_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    sender_key: u16,
    receiver_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
) -> HsmResult<Vec<u8>> {
    // Evidence is accepted for a forward-compatible signature but not yet
    // transmitted through the OOB transport. See module docs.
    let _ = receiver_evidence;

    let req = TborSdCreateRemoteBackupReq {
        session_id,
        sender_key,
        policy: decode_policy(policy)?,
        ..Default::default()
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let resp = dev
        .exec_op_tbor(&req, None, &mut cookie)
        .map_err(HsmError::from)?;
    Ok(resp.pok_remote_backup)
}

/// Issue `SdResealBackup` (opcode `0x0B`) on the active session.
///
/// Unmasks the caller-supplied `pok_remote_backup` under the named
/// sealing key and re-masks it for the destination, returning a freshly
/// resealed remote backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_handle` - Vault id of the sealing key the source
///   backup is bound to.
/// * `src_evidence` / `dest_evidence` - Source and destination
///   attestation evidence (**accepted but not yet transmitted**).
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_remote_backup` - Source masked backup ([`POK_BACKUP_LEN`]
///   bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy` or a
/// wrong-length backup, and surfaces DDI/device failures.
pub(crate) fn sd_reseal_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_handle: u16,
    src_evidence: &HsmSdEvidence<'_>,
    dest_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_remote_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    let _ = (src_evidence, dest_evidence);
    check_len(pok_remote_backup, POK_BACKUP_LEN)?;

    let req = TborSdResealBackupReq {
        session_id,
        sealing_key_handle,
        policy: decode_policy(policy)?,
        pok_remote_backup: pok_remote_backup.to_vec(),
        ..Default::default()
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let resp = dev
        .exec_op_tbor(&req, None, &mut cookie)
        .map_err(HsmError::from)?;
    Ok(resp.pok_remote_backup)
}

/// Issue `SdRestoreRemoteBackup` (opcode `0x0C`) on the active session.
///
/// Unmasks the caller-supplied `pok_remote_backup` under the named
/// sealing key, re-wraps it under the device-local key, and returns the
/// local backup together with the security-domain masking-key backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key the backup is bound
///   to.
/// * `sender_evidence` - Sender attestation evidence (**accepted but not
///   yet transmitted**).
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_remote_backup` - Remote masked backup ([`POK_BACKUP_LEN`]
///   bytes).
/// * `sd_mk_backup` - Optional masking-key backup envelope
///   ([`SD_MK_BACKUP_LEN`] bytes when present).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy` or a
/// wrong-length blob, and surfaces DDI/device failures.
pub(crate) fn sd_restore_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    sender_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_remote_backup: &[u8],
    sd_mk_backup: Option<&[u8]>,
) -> HsmResult<HsmSdRestoreResult> {
    let _ = sender_evidence;
    check_len(pok_remote_backup, POK_BACKUP_LEN)?;
    if let Some(mk) = sd_mk_backup {
        check_len(mk, SD_MK_BACKUP_LEN)?;
    }

    let req = TborSdRestoreRemoteBackupReq {
        session_id,
        sealing_key_id,
        policy: decode_policy(policy)?,
        pok_remote_backup: pok_remote_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.map(<[u8]>::to_vec).unwrap_or_default(),
        ..Default::default()
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, None, &mut cookie)
        .map(HsmSdRestoreResult::from)
        .map_err(HsmError::from)
}

/// Issue `SdRestoreLocalBackup` (opcode `0x0D`) on the active session.
///
/// Restores a security domain from its device-local backups, returning
/// the refreshed local partition-owner-key backup and masking-key backup
/// envelope. This command carries no attestation evidence.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `pok_local_backup` - Local masked backup ([`POK_BACKUP_LEN`] bytes).
/// * `sd_mk_backup` - Masking-key backup envelope ([`SD_MK_BACKUP_LEN`]
///   bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length blob, and
/// surfaces DDI/device failures.
pub(crate) fn sd_restore_local_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    pok_local_backup: &[u8],
    sd_mk_backup: &[u8],
) -> HsmResult<HsmSdRestoreResult> {
    check_len(pok_local_backup, POK_BACKUP_LEN)?;
    check_len(sd_mk_backup, SD_MK_BACKUP_LEN)?;

    let req = TborSdRestoreLocalBackupReq {
        session_id,
        pok_local_backup: pok_local_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.to_vec(),
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, None, &mut cookie)
        .map(HsmSdRestoreResult::from)
        .map_err(HsmError::from)
}

/// Issue `SdCreatePeerBackup` (opcode `0x0E`) on the active session.
///
/// Re-masks the caller-supplied `pok_local_backup` for the destination
/// peer under the named sealing key, returning the peer backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key the local backup is
///   bound to.
/// * `dst_evidence` - Destination peer attestation evidence (**accepted
///   but not yet transmitted**).
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_local_backup` - Local masked backup ([`POK_BACKUP_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy` or a
/// wrong-length backup, and surfaces DDI/device failures.
pub(crate) fn sd_create_peer_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    dst_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_local_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    let _ = dst_evidence;
    check_len(pok_local_backup, POK_BACKUP_LEN)?;

    let req = TborSdCreatePeerBackupReq {
        session_id,
        sealing_key_id,
        policy: decode_policy(policy)?,
        pok_local_backup: pok_local_backup.to_vec(),
        ..Default::default()
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let resp = dev
        .exec_op_tbor(&req, None, &mut cookie)
        .map_err(HsmError::from)?;
    Ok(resp.pok_peer_backup)
}

/// Issue `SdRestorePeerBackup` (opcode `0x0F`) on the active session.
///
/// Unmasks the caller-supplied `pok_peer_backup` under the named sealing
/// key, re-wraps it under the device-local key, and returns the local
/// backup together with the security-domain masking-key backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key the peer backup is
///   bound to.
/// * `src_evidence` - Source attestation evidence (**accepted but not yet
///   transmitted**).
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_peer_backup` - Peer masked backup ([`POK_BACKUP_LEN`] bytes).
/// * `sd_mk_backup` - Masking-key backup envelope ([`SD_MK_BACKUP_LEN`]
///   bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a malformed `policy` or a
/// wrong-length blob, and surfaces DDI/device failures.
pub(crate) fn sd_restore_peer_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    src_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_peer_backup: &[u8],
    sd_mk_backup: &[u8],
) -> HsmResult<HsmSdRestoreResult> {
    let _ = src_evidence;
    check_len(pok_peer_backup, POK_BACKUP_LEN)?;
    check_len(sd_mk_backup, SD_MK_BACKUP_LEN)?;

    let req = TborSdRestorePeerBackupReq {
        session_id,
        sealing_key_id,
        policy: decode_policy(policy)?,
        pok_peer_backup: pok_peer_backup.to_vec(),
        sd_mk_backup: sd_mk_backup.to_vec(),
        ..Default::default()
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, None, &mut cookie)
        .map(HsmSdRestoreResult::from)
        .map_err(HsmError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A correctly-sized ([`PART_POLICY_LEN`]) zeroed image decodes to the
    /// default policy; wrong lengths are rejected.
    #[test]
    fn decode_policy_enforces_length() {
        assert!(decode_policy(&[0u8; PART_POLICY_LEN]).is_ok());
        assert!(matches!(
            decode_policy(&[0u8; PART_POLICY_LEN - 1]),
            Err(HsmError::InvalidArgument)
        ));
        assert!(matches!(
            decode_policy(&[0u8; PART_POLICY_LEN + 1]),
            Err(HsmError::InvalidArgument)
        ));
    }

    /// Fixed-length backup blobs are validated against the wire lengths.
    #[test]
    fn check_len_enforces_exact_length() {
        assert!(check_len(&[0u8; POK_BACKUP_LEN], POK_BACKUP_LEN).is_ok());
        assert!(check_len(&[0u8; SD_MK_BACKUP_LEN], SD_MK_BACKUP_LEN).is_ok());
        assert!(matches!(
            check_len(&[0u8; POK_BACKUP_LEN - 1], POK_BACKUP_LEN),
            Err(HsmError::InvalidArgument)
        ));
    }
}
