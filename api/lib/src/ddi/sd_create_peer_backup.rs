// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SdCreatePeerBackup` (opcode `0x0E`) at the DDI layer.
//!
//! Creates a peer-transferable backup of a security domain: re-masks
//! the local partition-owner-key backup (`pok_local_backup`) for the
//! destination peer identified by `dst_evidence` under the named
//! sealing key, and returns the peer backup (`pok_peer_backup`).
//!
//! Runs **inside an already-open session** established by
//! [`super::session_ex::open_session_ex`].

use azihsm_ddi_tbor_types::*;

use super::*;

/// Bundles the cert-chain-plus-report "evidence" TOC group shared by
/// several `Sd*` commands.
///
/// Mirrors the firmware `Evidence` field group: the host `#[tbor]`
/// derive has no field-group support, so each wire request spells the
/// four TOC entries out as individual fields. This struct exists
/// purely to keep the DDI-layer call sites manageable.
pub(crate) struct SdEvidence<'a> {
    pub mfgr_cert_chain: &'a [CertDescriptor],
    pub owner_cert_chain: &'a [CertDescriptor],
    pub part_owner_cert_chain: &'a [CertDescriptor],
    pub report: ReportDescriptor,
}

/// Issue `SdCreatePeerBackup` (opcode `0x0E`) on the active session.
///
/// # Arguments
///
/// * `partition` - The HSM partition handle.
/// * `session_id` - The active session id this request binds to.
/// * `sealing_key_id` - Vault id of the sealing key `pok_local_backup`
///   is bound to.
/// * `dst_evidence` - Destination cert-chain / report descriptors.
/// * `part_policy` - Unified [`PartPolicy`] image ([`PART_POLICY_LEN`]
///   bytes) describing the security domain being backed up.
/// * `pok_local_backup` - Local partition-owner-key backup to re-mask
///   ([`MASKED_SD_LEN`] bytes).
///
/// # Errors
///
/// Returns [`HsmError::InvalidArgument`] when `part_policy` or
/// `pok_local_backup` have the wrong length, or `part_policy` fails to
/// decode; surfaces DDI/device failures from the round-trip.
pub(crate) fn sd_create_peer_backup(
    partition: &HsmPartition,
    session_id: u16,
    sealing_key_id: u16,
    dst_evidence: SdEvidence<'_>,
    part_policy: &[u8],
    pok_local_backup: &[u8],
) -> HsmResult<Vec<u8>> {
    if part_policy.len() != PART_POLICY_LEN || pok_local_backup.len() != MASKED_SD_LEN {
        return Err(HsmError::InvalidArgument);
    }

    let mut req = TborSdCreatePeerBackupReq {
        session_id,
        sealing_key_id,
        dst_mfgr_cert_chain: dst_evidence.mfgr_cert_chain.to_vec(),
        dst_owner_cert_chain: dst_evidence.owner_cert_chain.to_vec(),
        dst_part_owner_cert_chain: dst_evidence.part_owner_cert_chain.to_vec(),
        dst_report: dst_evidence.report,
        pok_local_backup: pok_local_backup.to_vec(),
        ..Default::default()
    };
    req.policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| HsmError::InvalidArgument)?;

    let inner = partition.inner().read();
    let dev = inner.dev();
    let mut cookie = None;
    dev.exec_op_tbor(&req, &mut cookie)
        .map(|resp| resp.pok_peer_backup)
        .map_err(HsmError::from)
}
