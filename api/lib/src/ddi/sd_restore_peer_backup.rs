// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdRestorePeerBackup` (opcode `0x0F`) over the TBOR transport at the DDI
//! layer.
//!
//! Restores a security domain from a **peer** backup: HPKE-Auth-opens the
//! caller-supplied `pok_peer_backup` (an HPKE seal of BKS3) with the
//! receiver's masked sealing key — authenticated by the source peer's
//! attested key — recovers `SDMK` from `prev_sd_mk_backup`, and returns the
//! device-local backups. Peer cloning is gated by the security domain's
//! `allow_peer_cloning` policy flag. Runs **inside an already-open
//! session**; the request carries the active session id, which the firmware
//! dispatcher cross-checks against the SQE-carried session id. Attestation
//! evidence travels out of band (see [`super::sd_evidence`]).

use azihsm_ddi_tbor_types::*;

use super::*;

/// Converts the wire `SdRestorePeerBackup` response into the owned
/// API-layer [`HsmSdRestoreResult`].
impl From<TborSdRestorePeerBackupResp> for HsmSdRestoreResult {
    fn from(resp: TborSdRestorePeerBackupResp) -> Self {
        Self {
            pok_local_backup: resp.pok_local_backup,
            sd_mk_backup: resp.sd_mk_backup,
        }
    }
}

/// Issue `SdRestorePeerBackup` (opcode `0x0F`) on the active session.
///
/// HPKE-opens `pok_peer_backup` with the receiver's `masked_sealing_key`
/// (authenticated by the source peer in `src_evidence`), recovers `SDMK`
/// from `prev_sd_mk_backup`, and returns the refreshed device-local
/// backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The receiver's masked SD-sealing key (from
///   `SdSealingKeyGen`) that unseals the backup, exactly
///   [`MASKED_SEALING_KEY_LEN`] bytes.
/// * `src_evidence` - Source (peer) attestation evidence (cert chains and
///   report), transmitted out of band.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_peer_backup` - The peer backup to restore, exactly
///   [`POK_REMOTE_BACKUP_LEN`] bytes.
/// * `prev_sd_mk_backup` - The previous security-domain masking-key backup,
///   exactly [`SD_MK_BACKUP_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key`, `pok_peer_backup`, or `prev_sd_mk_backup`, or a
/// malformed `policy`, and surfaces DDI/device failures from the round-trip
/// (including `SdPeerCloningNotAllowed` when the policy clears
/// `allow_peer_cloning`).
pub(crate) fn sd_restore_peer_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    src_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_peer_backup: &[u8],
    prev_sd_mk_backup: &[u8],
) -> HsmResult<HsmSdRestoreResult> {
    let masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN] = masked_sealing_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let pok_peer_backup: [u8; POK_REMOTE_BACKUP_LEN] = pok_peer_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let prev_sd_mk_backup: [u8; SD_MK_BACKUP_LEN] = prev_sd_mk_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    // Flatten the source evidence into descriptors + shared OOB items.
    let mut oob: Vec<&[u8]> = Vec::new();
    let src = push_evidence(src_evidence, &mut oob)?;

    let req = TborSdRestorePeerBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        src_mfgr_cert_chain: src.mfgr,
        src_owner_cert_chain: src.owner,
        src_part_owner_cert_chain: src.part_owner,
        src_report: src.report,
        pok_peer_backup,
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
