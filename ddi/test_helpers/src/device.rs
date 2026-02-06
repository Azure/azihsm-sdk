// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_get_device_info(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetDeviceInfoCmdResp, DdiError> {
    let req = DdiGetDeviceInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetDeviceInfo,
            sess_id,
            rev,
        },
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
