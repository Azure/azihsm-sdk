// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_close_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiCloseSessionCmdResp, DdiError> {
    let req = DdiCloseSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::CloseSession,
            sess_id,
            rev,
        },
        data: DdiCloseSessionReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_open_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    encrypted_credential: DdiEncryptedSessionCredential,
    pub_key: DdiDerPublicKey,
) -> Result<DdiOpenSessionCmdResp, DdiError> {
    let req = DdiOpenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenSession,
            sess_id,
            rev,
        },
        data: DdiOpenSessionReq {
            encrypted_credential,
            pub_key,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_reopen_session(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: u16,
    rev: Option<DdiApiRev>,
    encrypted_credential: DdiEncryptedSessionCredential,
    pub_key: DdiDerPublicKey,
    bmk_session: MborByteArray<1024>,
) -> Result<DdiReopenSessionCmdResp, DdiError> {
    let req = DdiReopenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::ReopenSession,
            sess_id: Some(sess_id),
            rev,
        },
        data: DdiReopenSessionReq {
            encrypted_credential,
            pub_key,
            bmk_session,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
