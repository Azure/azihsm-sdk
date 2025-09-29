// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub fn helper_aes_generate(
    dev: &<DdiTest as Ddi>::Dev,
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
    dev: &<DdiTest as Ddi>::Dev,
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

pub fn helper_soft_aes_op(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    kek_len: usize,
    kek: &[u8],
    msg_len: usize,
    msg: &[u8],
    req_op: DdiSoftAesOp,
) -> DdiResult<DdiSoftAesCmdResp> {
    const MAX_KEY_LEN: usize = 32;
    const MAX_MSG_LEN: usize = 1024;

    let req = DdiSoftAesCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::SoftAes,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiSoftAesReq {
            key: MborByteArray::new(
                {
                    let mut data = [0u8; MAX_KEY_LEN];
                    data[..kek_len].copy_from_slice(kek);
                    data
                },
                kek_len,
            )
            .expect("failed to create byte array"),
            inout: MborByteArray::new(
                {
                    let mut data = [0u8; MAX_MSG_LEN];
                    data[..msg_len].copy_from_slice(msg);
                    data
                },
                msg_len,
            )
            .expect("failed to create byte array"),
            op: req_op,
        },
        ext: None,
    };

    let mut cookie = None;
    dev.exec_op(&req, &mut cookie)
}
