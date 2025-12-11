// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_get_rng(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    rng_len: u8,
) -> Result<DdiGetRngGenerateCmdResp, DdiError> {
    let req = DdiGetRngGenerateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetRandomNumber,
            sess_id,
            rev,
        },
        data: DdiGetRngGenerateReq { rng_len },
        ext: None,
    };

    let mut cookie = None;

    dev.exec_op(&req, &mut cookie)
}
