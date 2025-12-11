// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use super::*;

pub fn hmac_sign(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    msg: &[u8],
) -> Result<DdiHmacCmdResp, DdiError> {
    let req = DdiHmacCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::Hmac,
            sess_id,
            rev,
        },
        data: DdiHmacReq {
            key_id,
            msg: MborByteArray::from_slice(msg)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
