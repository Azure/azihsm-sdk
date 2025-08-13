// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_unmask_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    masked_key: MborByteArray<3072>,
) -> Result<DdiUnmaskKeyCmdResp, DdiError> {
    let req = DdiUnmaskKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::UnmaskKey,
            sess_id,
            rev,
        },
        data: DdiUnmaskKeyReq { masked_key },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
