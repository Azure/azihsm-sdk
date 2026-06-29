// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Helper for the TBOR `PartFinal` command.
//!
//! Re-supplies the unified `PartPolicy` (so the device can re-derive
//! `POTAPubKey` and verify `SHA-384(part_policy) == policy_hash`) along
//! with a placeholder PTA cert-chain descriptor (the firmware handler
//! does not yet walk the chain) and an optional prior `local_mk` backup
//! to restore.

use azihsm_ddi::AzihsmDdi;
use azihsm_ddi_interface::Ddi;
use azihsm_ddi_interface::DdiDev;
use azihsm_ddi_interface::DdiError;
use azihsm_ddi_tbor_types::CertDescriptor;
use azihsm_ddi_tbor_types::PartPolicy;
use azihsm_ddi_tbor_types::TborPartFinalReq;
use azihsm_ddi_tbor_types::TborPartFinalResp;
use azihsm_ddi_tbor_types::PART_POLICY_LEN;

use super::finish::SessionHandshake;

/// Issue `PartFinal` on the CO session represented by `session`.
///
/// `part_policy` must be exactly [`PART_POLICY_LEN`] and match the policy
/// bound at `PartInit`.  `prev_local_mk_backup` is the optional prior
/// backup to restore (empty = first instantiation).
pub fn part_final(
    dev: &<AzihsmDdi as Ddi>::Dev,
    session: &SessionHandshake,
    part_policy: &[u8],
    prev_local_mk_backup: &[u8],
) -> Result<TborPartFinalResp, DdiError> {
    if part_policy.len() != PART_POLICY_LEN {
        return Err(DdiError::InvalidParameter);
    }
    let policy = <PartPolicy as zerocopy::TryFromBytes>::try_read_from_bytes(part_policy)
        .map_err(|_| DdiError::InvalidParameter)?;

    let req = TborPartFinalReq {
        session_id: session.session_id,
        part_policy: policy,
        // The wire schema requires ≥1 cert descriptor; the firmware
        // handler ignores it (cert-chain walking is not yet implemented).
        cert_descriptors: vec![CertDescriptor::default()],
        prev_local_mk_backup: prev_local_mk_backup.to_vec(),
    };

    dev.exec_op_tbor(&req, &mut None)
}
