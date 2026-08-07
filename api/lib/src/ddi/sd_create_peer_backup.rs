// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreatePeerBackup` (opcode `0x0E`) over the TBOR transport at the DDI
//! layer.
//!
//! Creates a peer-transferable backup of a security domain: recovers BKS3
//! from the caller's device-local backup (`pok_local_backup`) and
//! HPKE-Auth-seals it to the destination peer named by `dst_evidence` —
//! authenticated by the sender's own masked SD-sealing key — returning the
//! peer backup (`pok_peer_backup`). Peer cloning is gated by the security
//! domain's `allow_peer_cloning` policy flag. Runs **inside an already-open
//! session**; the request carries the active session id, which the firmware
//! dispatcher cross-checks against the SQE-carried session id. Attestation
//! evidence travels out of band (see [`super::sd_evidence`]).

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdCreatePeerBackup` (opcode `0x0E`) on the active session.
///
/// Recovers BKS3 from `pok_local_backup` and HPKE-Auth-seals it to the
/// destination peer in `dst_evidence` (authenticated by the sender's
/// `masked_sealing_key`), returning the peer backup.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The sender's masked SD-sealing key (from
///   `SdSealingKeyGen`), exactly [`MASKED_SEALING_KEY_LEN`] bytes.
/// * `dst_evidence` - Destination (peer) attestation evidence (cert chains
///   and report), transmitted out of band.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
/// * `pok_local_backup` - The device-local partition-owner-key backup from
///   which BKS3 is recovered, exactly [`MASKED_SD_LEN`] bytes.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key` or `pok_local_backup`, or a malformed `policy`, and
/// surfaces DDI/device failures from the round-trip (including
/// `SdPeerCloningNotAllowed` when the policy clears `allow_peer_cloning`).
pub(crate) fn sd_create_peer_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    dst_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
    pok_local_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    let masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN] = masked_sealing_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let pok_local_backup: [u8; MASKED_SD_LEN] = pok_local_backup
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    // Flatten the destination evidence into descriptors + shared OOB items.
    let mut oob: Vec<&[u8]> = Vec::new();
    let dst = push_evidence(dst_evidence, &mut oob)?;

    let req = TborSdCreatePeerBackupReq {
        session_id,
        masked_sealing_key,
        policy,
        dst_mfgr_cert_chain: dst.mfgr,
        dst_owner_cert_chain: dst.owner,
        dst_part_owner_cert_chain: dst.part_owner,
        dst_report: dst.report,
        pok_local_backup,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    dev.exec_op_tbor(&req, oob_items, &mut cookie)
        .map(|resp| resp.pok_peer_backup.to_vec())
        .map_err(HsmError::from)
}
