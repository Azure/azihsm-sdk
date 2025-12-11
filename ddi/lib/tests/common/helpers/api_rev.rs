// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_get_api_rev_op(
    dev: &<DdiTest as Ddi>::Dev,
    op: DdiOp,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetApiRevCmdResp, DdiError> {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr { op, sess_id, rev },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_api_rev(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetApiRevCmdResp, DdiError> {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id,
            rev,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_api_rev_ext(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetApiRevCmdResp, DdiError> {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id,
            rev,
        },
        data: DdiGetApiRevReq {},
        ext: Some(DdiReqExt {}),
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
