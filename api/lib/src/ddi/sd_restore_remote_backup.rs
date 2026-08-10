// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestoreRemoteBackup` (opcode `0x0C`) over the TBOR transport at the
//! DDI layer.
//!
//! Restores a security domain from a **remote** backup: HPKE-Auth-opens the
//! caller-supplied `src_remote_backup` (an HPKE seal of BKS3) with the
//! receiver's masked sealing key — authenticated by the sender's attested
//! key — recovers `SDMK` from `prev_sd_mk_backup`, and returns the
//! device-local backups so the domain can later be restored locally without
//! the sender. Runs **inside an already-open session**; the request carries
//! the active session id, which the firmware dispatcher cross-checks against
//! the SQE-carried session id. Attestation evidence travels out of band
//! (see [`super::sd_evidence`]).

use azihsm_ddi_tbor_types::*;

use super::*;

/// Converts the wire `SdRestoreRemoteBackup` response into the owned
/// API-layer [`HsmSdRestoreResult`].
impl From<TborSdRestoreRemoteBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestoreRemoteBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestoreRemoteBackup` (opcode `0x0C`) on the active session.
///
/// HPKE-opens `src_remote_backup` with the receiver's `masked_sealing_key`
/// (authenticated by the sender key in `sender_evidence`), recovers `SDMK`
/// from `prev_sd_mk_backup`, and returns the refreshed device-local backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The receiver's masked SD-sealing key (from
///   `SdSealingKeyGen`) that unseals the backup, exactly
///   [`MASKED_SEALING_KEY_LEN`] bytes.
/// * `sender_evidence` - Sender attestation evidence (cert chains and
///   report), transmitted out of band.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `src_remote_backup` - The remote backup to restore, exactly
///   [`POK_REMOTE_BACKUP_LEN`] bytes.
/// * `prev_sd_mk_backup` - The previous security-domain masking-key backup,
///   exactly [`SD_MK_BACKUP_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key`, `src_remote_backup`, or `prev_sd_mk_backup`, or a
/// malformed `policy`, and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_restore_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    sender_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    src_remote_backup: &[u8],
    prev_sd_mk_backup: &[u8],
) -> HsmResult<HsmSdRestoreResult> {
    let masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN] = masked_sealing_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN] = src_remote_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN] = prev_sd_mk_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    // Flatten the sender evidence into descriptors + shared OOB items.
    let mut oob: Vec<&[u8]> = Vec::new();
    let sender = push_evidence(sender_evidence, &mut oob)?;

    let req = TborSdRestoreRemoteBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        sender_mfgr_cert_chain: sender.mfgr,
        sender_owner_cert_chain: sender.owner,
        sender_part_owner_cert_chain: sender.part_owner,
        sender_report: sender.report,
        src_remote_backup,
        prev_sd_mk_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    dev.exec_op_tbor(&req, oob_items, &mut cookie)
        .map(HsmSdRestoreResult::from)
        .map_err(HsmError::from)
}
