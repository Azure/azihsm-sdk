// Copyright (C) Microsoft Corporation. All rights reserved.
use super::*;

pub fn helper_delete_key(
    dev: &<DdiTest as Ddi>::Dev,
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

pub fn helper_open_key(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_tag: u16,
) -> Result<DdiOpenKeyCmdResp, DdiError> {
    let req = DdiOpenKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenKey,
            sess_id,
            rev,
        },
        data: DdiOpenKeyReq { key_tag },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
