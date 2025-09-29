// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
pub fn helper_init_bk3(
    dev: &<DdiTest as Ddi>::Dev,
    bk3: Vec<u8>,
) -> Result<DdiInitBk3CmdResp, DdiError> {
    let req = DdiInitBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::InitBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiInitBk3Req {
            bk3: MborByteArray::from_slice(&bk3).expect("failed to create byte array"),
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
