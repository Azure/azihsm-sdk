// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_sha_digest(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    msg: MborByteArray<1024>,
    sha_mode: DdiHashAlgorithm,
) -> Result<DdiShaDigestGenerateCmdResp, DdiError> {
    let req = DdiShaDigestGenerateCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ShaDigest,
            sess_id,
            rev,
        },
        data: DdiShaDigestGenerateReq { sha_mode, msg },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
