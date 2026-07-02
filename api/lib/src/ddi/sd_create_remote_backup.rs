// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreateRemoteBackup` (opcode `0x0A`) at the DDI layer.
//!
//! Creates a new security domain under the active CO session's
//! partition from the caller-supplied unified `PartPolicy`, returning
//! the remote partition-owner-key backup (`pok_remote_backup`).
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdCreateRemoteBackup` (opcode `0x0A`) on the active CO
/// session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active CO session id this request binds to.
/// * `sender_key` - Vault id the masked security domain is wrapped
///   under.
/// * `receiver_evidence` - Receiver cert-chain / report descriptors.
/// * `part_policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`]
///   bytes) describing the security domain to create.
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `part_policy` has the
/// wrong length or fails to decode; surfaces DDI/device failures from
/// the round-trip.
pub(crate) fn sd_create_remote_backup(
    partition: &HsmPartition,
    session_id: u16,
    sender_key: u16,
    receiver_evidence: SdEvidence<'_>,
    part_policy: &[u8],
) -> HsmResult<Vec<u8>> {
    if part_policy.len() != PART_POLICY_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let mut req = TborSdCreateRemoteBackupReq {
        session_id,
        sender_key,
        receiver_mfgr_cert_chain: receiver_evidence.mfgr_cert_chain.to_vec(),
        receiver_owner_cert_chain: receiver_evidence.owner_cert_chain.to_vec(),
        receiver_part_owner_cert_chain: receiver_evidence.part_owner_cert_chain.to_vec(),
        receiver_report: receiver_evidence.report,
        ..Default::default()
    };
    req.policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| HsmError::InvalidArgument)?;

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(|resp| resp.pok_remote_backup)
        .map_err(HsmError::from)
}
