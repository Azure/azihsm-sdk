// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn get_api_rev(dev: &<HsmDdi as Ddi>::Dev) -> Result<DdiGetApiRevCmdResp, DdiError> {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id: None,
            rev: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
