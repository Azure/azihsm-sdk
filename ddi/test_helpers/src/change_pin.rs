// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_change_pin(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    new_pin: DdiEncryptedPin,
    pub_key: DdiDerPublicKey,
) -> Result<DdiChangePinCmdResp, DdiError> {
    let req = DdiChangePinCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ChangePin,
            sess_id,
            rev,
        },
        data: DdiChangePinReq { new_pin, pub_key },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
