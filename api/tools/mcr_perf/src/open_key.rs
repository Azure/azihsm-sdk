// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_open_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_tag: u16,
) -> DdiResult<()> {
    let req = DdiOpenKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiOpenKeyReq { key_tag },
        ext: None,
    };

    let mut cookie = None;

    let _resp: DdiOpenKeyCmdResp = dev.exec_op(&req, &mut cookie)?;
    Ok(())
}

pub(crate) fn helper_open_key_return_key_id(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_tag: u16,
) -> DdiResult<u16> {
    let req = DdiOpenKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiOpenKeyReq { key_tag },
        ext: None,
    };

    let mut cookie = None;

    let resp: DdiOpenKeyCmdResp = dev.exec_op(&req, &mut cookie)?;
    Ok(resp.data.key_id)
}
