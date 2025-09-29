// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_sim::report::REPORT_DATA_SIZE;

use super::*;

pub fn helper_hmac(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    msg: MborByteArray<1024>,
) -> Result<DdiHmacCmdResp, DdiError> {
    let req = DdiHmacCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::Hmac,
            sess_id,
            rev,
        },
        data: DdiHmacReq { key_id, msg },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
