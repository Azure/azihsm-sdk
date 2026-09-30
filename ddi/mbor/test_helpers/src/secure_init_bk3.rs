// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_set_init_bk3_pin(
    dev: &<AzihsmDdi as Ddi>::Dev,
    encrypted_credential: DdiEncryptedEstablishCredential,
    pub_key: DdiDerPublicKey,
) -> Result<DdiSetInitBk3PinCmdResp, DdiError> {
    let req = DdiSetInitBk3PinCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::SetInitBk3Pin,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiSetInitBk3PinReq {
            encrypted_credential,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op_mbor(&req, &mut cookie)
}

pub fn helper_secure_init_bk3(
    dev: &<AzihsmDdi as Ddi>::Dev,
    encrypted_bk3: DdiEncryptedBk3,
    pub_key: DdiDerPublicKey,
) -> Result<DdiSecureInitBk3CmdResp, DdiError> {
    let req = DdiSecureInitBk3CmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::SecureInitBk3,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiSecureInitBk3Req {
            encrypted_bk3,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op_mbor(&req, &mut cookie)
}
