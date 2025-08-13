// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_get_api_rev(dev: &<DdiTest as Ddi>::Dev) -> DdiResult<()> {
    let req = DdiGetApiRevCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetApiRev,
            sess_id: None,
            rev: None,
        },
        data: DdiGetApiRevReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_get_device_info(
    dev: &<DdiTest as Ddi>::Dev,
) -> DdiResult<DdiGetDeviceInfoResp> {
    let req = DdiGetDeviceInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetDeviceInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|info| (info.data))
}

pub(crate) fn helper_set_device_kind(dev: &mut <DdiTest as Ddi>::Dev) -> DdiResult<()> {
    let resp = helper_get_device_info(dev)?;
    dev.set_device_kind(resp.kind);
    Ok(())
}
