// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

pub fn helper_delete_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
) -> Result<DdiDeleteKeyCmdResp, DdiError> {
    let req = DdiDeleteKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DeleteKey,
            sess_id,
            rev,
        },
        data: DdiDeleteKeyReq { key_id },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_open_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_tag: u16,
) -> Result<DdiOpenKeyCmdResp, DdiError> {
    let req = DdiOpenKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::OpenKey,
            sess_id,
            rev,
        },
        data: DdiOpenKeyReq { key_tag },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_establish_cred_encryption_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetEstablishCredEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetEstablishCredEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetEstablishCredEncryptionKey,
            sess_id,
            rev,
        },
        data: DdiGetEstablishCredEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_session_encryption_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetSessionEncryptionKeyCmdResp, DdiError> {
    let req = DdiGetSessionEncryptionKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetSessionEncryptionKey,
            sess_id,
            rev,
        },
        data: DdiGetSessionEncryptionKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_get_unwrapping_key(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
) -> Result<DdiGetUnwrappingKeyCmdResp, DdiError> {
    let req = DdiGetUnwrappingKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetUnwrappingKey,
            sess_id,
            rev,
        },
        data: DdiGetUnwrappingKeyReq {},
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
