// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn get_device_info(
    dev: &<HsmDdi as Ddi>::Dev,
    rev: DdiApiRev,
) -> Result<DdiGetDeviceInfoCmdResp, DdiError> {
    let req = DdiGetDeviceInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetDeviceInfo,
            sess_id: None,
            rev: Some(rev),
        },
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
