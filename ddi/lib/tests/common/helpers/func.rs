// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_reset_function(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiResetFunctionCmdResp, DdiError> {
    let req = DdiResetFunctionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ResetFunction,
            sess_id,
            rev,
        },
        data: DdiResetFunctionReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
