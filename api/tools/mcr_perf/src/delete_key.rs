// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_delete_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
) -> DdiResult<()> {
    let req = DdiDeleteKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DeleteKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}
