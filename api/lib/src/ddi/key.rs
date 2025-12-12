// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn delete_key(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
) -> Result<DdiDeleteKeyCmdResp, DdiError> {
    let req = DdiDeleteKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DeleteKey,
            sess_id,
            rev,
        },
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
