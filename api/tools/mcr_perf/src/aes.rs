// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn helper_aes_encrypt_decrypt(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_id: u16,
    msg: [u8; 1024],
    msg_len: usize,
    mode: DdiAesOp,
) -> DdiResult<()> {
    let req = DdiAesEncryptDecryptCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AesEncryptDecrypt,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiAesEncryptDecryptReq {
            key_id,
            op: mode,
            msg: MborByteArray::new(msg, msg_len).expect("failed to create byte array"),
            iv: MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|_| ())
}

pub(crate) fn helper_create_aes_key(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_size: DdiAesKeySize,
    key_tag: Option<u16>,
) -> DdiResult<(u16, Option<u16>)> {
    let req = DdiAesGenerateKeyCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::AesGenerateKey,
            sess_id: Some(app_sess_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiAesGenerateKeyReq {
            key_size,
            key_tag,
            key_properties: helper_key_properties(
                DdiKeyUsage::EncryptDecrypt,
                DdiKeyAvailability::App,
            ),
        },
        ext: None,
    };

    let mut cookie = None;

    let resp = dev.exec_op(&req, &mut cookie);
    resp.map(|resp| (resp.data.key_id, resp.data.bulk_key_id))
}

pub(crate) fn helper_create_aes_cbc_key_and_delete(
    dev: &<DdiTest as Ddi>::Dev,
    app_sess_id: u16,
    key_size: DdiAesKeySize,
    key_tag: Option<u16>,
) -> DdiResult<()> {
    let (key_id, _) = helper_create_aes_key(dev, app_sess_id, key_size, key_tag)?;

    helper_delete_key(dev, app_sess_id, key_id)
}
