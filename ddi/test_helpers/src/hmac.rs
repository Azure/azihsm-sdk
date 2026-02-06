// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_hmac(
    dev: &<AzihsmDdi as Ddi>::Dev,
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
