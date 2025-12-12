// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn get_session_encryption_key(
    dev: &<HsmDdi as Ddi>::Dev,
    rev: DdiApiRev,
) -> Result<DdiGetSessionEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetSessionEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSessionEncryptionKey,
            sess_id: None,
            rev: Some(rev),
        },
        data: DdiGetSessionEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn close_session(
    dev: &<HsmDdi as Ddi>::Dev,
    sess_id: u16,
    rev: DdiApiRev,
) -> Result<DdiCloseSessionCmdResp, DdiError> {
    let req = DdiCloseSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::CloseSession,
            sess_id: Some(sess_id),
            rev: Some(rev),
        },
        data: DdiCloseSessionReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn open_session(
    dev: &<HsmDdi as Ddi>::Dev,
    rev: DdiApiRev,
    encrypted_credential: DdiEncryptedSessionCredential,
    pub_key: DdiDerPublicKey,
) -> Result<DdiOpenSessionCmdResp, DdiError> {
    let req = DdiOpenSessionCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenSession,
            sess_id: None,
            rev: Some(rev),
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

/*
pub fn reopen_session(
    dev: &<HsmDdi as Ddi>::Dev,
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
*/
