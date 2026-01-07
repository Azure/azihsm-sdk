// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_aes_generate(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_size: DdiAesKeySize,
    key_tag: Option<u16>,
    key_properties: DdiKeyProperties,
) -> Result<DdiAesGenerateKeyCmdResp, DdiError> {
    let req = DdiAesGenerateKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AesGenerateKey,
            sess_id,
            rev,
        },
        data: DdiAesGenerateKeyReq {
            key_size,
            key_tag,
            key_properties: key_properties
                .try_into()
                .map_err(|_| DdiError::InvalidParameter)?,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}

pub fn helper_aes_encrypt_decrypt(
    dev: &<AzihsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    op: DdiAesOp,
    msg: MborByteArray<1024>,
    iv: MborByteArray<16>,
) -> Result<DdiAesEncryptDecryptCmdResp, DdiError> {
    let req = DdiAesEncryptDecryptCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AesEncryptDecrypt,
            sess_id,
            rev,
        },
        data: DdiAesEncryptDecryptReq {
            key_id,
            op,
            msg,
            iv,
        },
        ext: None,
    };
    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
