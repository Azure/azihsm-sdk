// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_ecc_generate_key_pair(
    dev: &<DdiTest as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    curve: DdiEccCurve,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiEccGenerateKeyPairCmdResp, DdiError> {
    let req = DdiEccGenerateKeyPairCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::EccGenerateKeyPair,
            sess_id,
            rev,
        },
        data: DdiEccGenerateKeyPairReq {
            curve,
            key_tag,
            key_properties,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
