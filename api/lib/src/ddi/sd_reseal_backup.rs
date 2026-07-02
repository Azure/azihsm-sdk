// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdResealBackup` (opcode `0x0B`) at the DDI layer.
//!
//! Re-masks an existing security-domain blob (`pok_remote_backup`) for
//! a new recipient: unmasks the caller-supplied `pok_remote_backup`
//! under the named sealing key and re-masks it under the destination,
//! returning a freshly resealed `pok_remote_backup`.
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

/// Issue `SdResealBackup` (opcode `0x0B`) on the active session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_handle` - Vault id of the sealing key the source
///   `pok_remote_backup` is bound to.
/// * `part_policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`]
///   bytes) describing the security domain being resealed.
/// * `src_evidence` - Source cert-chain / report descriptors.
/// * `dest_evidence` - Destination cert-chain / report descriptors.
/// * `pok_remote_backup` - Masked security-domain blob to reseal
///   ([`MASKED_SD_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `part_policy` or
/// `pok_remote_backup` have the wrong length, or `part_policy` fails
/// to decode; surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_reseal_backup(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_handle: u16,
    part_policy: &[u8],
    src_evidence: SdEvidence<'_>,
    dest_evidence: SdEvidence<'_>,
    pok_remote_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    if part_policy.len() != PART_POLICY_LEN || pok_remote_backup.len() != MASKED_SD_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let mut req = TborSdResealBackupReq {
        session_id,
        sealing_key_handle,
        src_mfgr_cert_chain: src_evidence.mfgr_cert_chain.to_vec(),
        src_owner_cert_chain: src_evidence.owner_cert_chain.to_vec(),
        src_part_owner_cert_chain: src_evidence.part_owner_cert_chain.to_vec(),
        src_report: src_evidence.report,
        dest_mfgr_cert_chain: dest_evidence.mfgr_cert_chain.to_vec(),
        dest_owner_cert_chain: dest_evidence.owner_cert_chain.to_vec(),
        dest_part_owner_cert_chain: dest_evidence.part_owner_cert_chain.to_vec(),
        dest_report: dest_evidence.report,
        pok_remote_backup: pok_remote_backup.to_vec(),
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
