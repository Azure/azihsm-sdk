// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
pub fn helper_get_sealed_bk3(
    dev: &<AzihsmDdi as Ddi>::Dev,
) -> Result<DdiGetSealedBk3CmdResp, DdiError> {
    let req = DdiGetSealedBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSealedBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetSealedBk3Req {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
