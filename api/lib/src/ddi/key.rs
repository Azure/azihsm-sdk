// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// Deletes a key from the HSM.
///
/// Removes the specified key from the HSM partition, making it no longer usable
/// for cryptographic operations. This is a permanent operation that cannot be undone.
///
/// # Arguments
///
/// * `session` - The HSM session context
/// * `key_id` - The HSM key handle identifying the key to delete
///
/// # Returns
///
/// Returns `Ok(())` on successful deletion.
///
pub(crate) fn delete_key(session: &HsmSession, key_id: u16) -> HsmResult<()> {
    let req = DdiDeleteKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DeleteKey,
            rev: Some(session.api_rev().into()),
            sess_id: Some(session.id()),
        },
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    session.with_dev(|dev| {
        dev.exec_op(&req, &mut None)
            .map_hsm_err(HsmError::DdiCmdFailure)
    })?;

    Ok(())
}
