// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreateRemoteBackup` (opcode `0x0A`) over the TBOR transport at the
//! DDI layer.
//!
//! Creates a new security domain from a caller-supplied unified
//! `PartPolicy`, returning the remote partition-owner-key backup together
//! with the device-local partition-owner-key and security-domain
//! masking-key backups. Runs **inside an already-open session**; the
//! request carries the active session id, which the firmware dispatcher
//! cross-checks against the SQE-carried session id. Attestation evidence
//! travels out of band (see [`super::sd_evidence`]).

use azihsm_ddi_tbor_types::*;

use super::*;

/// Converts the wire `SdCreateRemoteBackup` response into the owned
/// API-layer [`HsmSdRemoteBackupResult`].
impl From<TborSdCreateRemoteBackupResp> for HsmSdRemoteBackupResult {
    fn from(resp: TborSdCreateRemoteBackupResp) -> Self {
        Self {
            pok_remote_backup: resp.pok_remote_backup.to_vec(),
            pok_local_backup: resp.pok_local_backup.to_vec(),
            sd_mk_backup: resp.sd_mk_backup.to_vec(),
        }
    }
}

/// Issue `SdCreateRemoteBackup` (opcode `0x0A`) on the active session.
///
/// Creates a new security domain from the caller-supplied unified
/// `policy`, using the sender's masked sealing key and the receiver's
/// attestation evidence, and returns the remote backup together with the
/// device-local backups.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `masked_sealing_key` - The sender's masked SD-sealing key (from
///   `SdSealingKeyGen`), exactly [`MASKED_SEALING_KEY_LEN`] bytes.
/// * `receiver_evidence` - Receiver attestation evidence (cert chains and
///   report), transmitted out of band.
/// * `policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] for a wrong-length
/// `masked_sealing_key` or a malformed `policy`, and surfaces DDI/device
/// failures from the round-trip.
pub(crate) fn sd_create_remote_backup_ex(
    partition: &HsmPartition,
    session_id: u16,
    masked_sealing_key: &[u8],
    receiver_evidence: &HsmSdEvidence<'_>,
    policy: &[u8],
) -> HsmResult<HsmSdRemoteBackupResult> {
    // Exact-length array conversion enforces MASKED_SEALING_KEY_LEN.
    let masked_sealing_key: [u8; MASKED_SEALING_KEY_LEN] = masked_sealing_key
        .try_into()
        .map_err(|_| HsmError::InvalidArgument)?;
    let policy = decode_policy(policy)?;

    // Flatten the receiver evidence into descriptors + shared OOB items.
    let mut oob: Vec<&[u8]> = Vec::new();
    let receiver = push_evidence(receiver_evidence, &mut oob)?;

    let req = TborSdCreateRemoteBackupReq {
        session_id,
        masked_sealing_key,
        receiver_mfgr_cert_chain: receiver.mfgr,
        receiver_owner_cert_chain: receiver.owner,
        receiver_part_owner_cert_chain: receiver.part_owner,
        receiver_report: receiver.report,
        policy,
    };

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    let oob_items = (!oob.is_empty()).then_some(oob.as_slice());
    dev.exec_op_tbor(&req, oob_items, &mut cookie)
        .map(HsmSdRemoteBackupResult::from)
        .map_err(HsmError::from)
}
