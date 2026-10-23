// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Execution helper for the `GetPrivKey` validation command.

use crate::common::*;

/// Read back a key's private material from validation firmware.
pub fn helper_get_priv_key(
    dev: &<azihsm_ddi::AzihsmDdi as azihsm_ddi::Ddi>::Dev,
    session_id: Option<u16>,
    key_id: u16,
) -> azihsm_ddi::DdiResult<DdiGetPrivKeyCmdResp> {
    use azihsm_ddi::DdiDev;
    use azihsm_ddi::DdiError;

    let data = DdiTestActionReq::encode(DdiTestAction::GetPrivKey, &DdiGetPrivKeyReq { key_id })
        .map_err(|_| DdiError::InvalidParameter)?;
    let req = DdiGetPrivKeyCmdReq {
        hdr: test_action_header(session_id),
        data,
        ext: None,
    };
    dev.exec_op_mbor(&req, &mut None)
}
