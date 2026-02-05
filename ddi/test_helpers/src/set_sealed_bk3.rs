// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
pub fn helper_set_sealed_bk3(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sealed_bk3: Vec<u8>,
) -> Result<DdiSetSealedBk3CmdResp, DdiError> {
    let req = DdiSetSealedBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::SetSealedBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiSetSealedBk3Req {
            sealed_bk3: MborByteArray::from_slice(&sealed_bk3)
                .expect("failed to create byte array"),
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
