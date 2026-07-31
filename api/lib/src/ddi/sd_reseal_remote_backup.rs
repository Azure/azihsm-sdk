// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdResealRemoteBackup` (opcode `0x0B`) over the TBOR transport at the
//! DDI layer.
//!
//! Reseals an existing remote backup from a source recipient to a
//! destination recipient. Runs **inside an already-open session**; the
//! request carries the active session id, which the firmware dispatcher
//! cross-checks against the SQE-carried session id. Attestation evidence
//! travels out of band (see [`super::sd_evidence`]).

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdResealRemoteBackup` (opcode `0x0B`) on the active session.
///
/// HPKE-opens `src_remote_backup` with the receiver's `masked_sealing_key`
/// (authenticated by the source sender key in `src_evidence`) and reseals
/// the recovered backup to the destination receiver (`dest_evidence`),
/// returning the resealed remote backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The receiver's masked SD-sealing key (from
///   `SdSealingKeyGen`) that unseals the source backup, exactly
///   [`MASKED_SEALING_KEY_LEN`] bytes.
/// * `src_evidence` - Source (sender) attestation evidence, transmitted
///   out of band.
/// * `dest_evidence` - Destination (receiver) attestation evidence.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `src_remote_backup` - The source remote backup to reseal, exactly
///   [`POK_REMOTE_BACKUP_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key` or `src_remote_backup`, or a malformed `policy`,
/// and surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_reseal_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    src_evidence: &HsmSdEvidence<'_>,
    dest_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    src_remote_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    let masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN] = masked_sealing_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let src_remote_backup: [u8; POK_REMOTE_BACKUP_LEN] = src_remote_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    // Both parties' evidence share one OOB list; push the source first,
    // then the destination, so descriptor indices stay contiguous.
    let mut oob: Vec<&[u8]> = Vec::new();
    let src = push_evidence(src_evidence, &mut oob)?;
    let dest = push_evidence(dest_evidence, &mut oob)?;

    let req = TborSdResealRemoteBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        src_mfgr_cert_chain: src.mfgr,
        src_owner_cert_chain: src.owner,
        src_part_owner_cert_chain: src.part_owner,
        src_report: src.report,
        dest_mfgr_cert_chain: dest.mfgr,
        dest_owner_cert_chain: dest.owner,
        dest_part_owner_cert_chain: dest.part_owner,
        dest_report: dest.report,
        src_remote_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    dev.exec_op_tbor(&req, oob_items, &mut cookie)
        .map(|resp| resp.dst_remote_backup.to_vec())
        .map_err(HsmError::from)
}
