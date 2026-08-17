// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Submit a `ShaDigest` command over the given message and return the
/// response. `sess_id` carries the caller's open session; `ShaDigest` is an
/// in-session command, so a valid session id is required for the request to
/// reach the firmware handler.
pub fn helper_sha_digest(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    msg: MborByteArray<1024>,
    sha_mode: DdiHashAlgorithm,
) -> Result<DdiShaDigestCmdResp, DdiError> {
    let req = DdiShaDigestCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ShaDigest,
            sess_id,
            rev,
        },
        data: DdiShaDigestReq { sha_mode, msg },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op_mbor(&req, &mut cookie)
}
