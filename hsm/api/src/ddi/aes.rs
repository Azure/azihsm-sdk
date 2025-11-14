// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

pub(crate) fn aes_generate_key(
    dev: &<HsmDdi as Ddi>::Dev,
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

pub(crate) fn aes_enc_dec(
    partition: &<HsmDdi as Ddi>::Dev,
    sess_id: Option<u16>,
    rev: Option<DdiApiRev>,
    key_id: u16,
    op: DdiAesOp,
    input: &[u8],
    iv: &[u8],
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
            msg: MborByteArray::from_slice(input)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
            iv: MborByteArray::from_slice(iv)
                .map_err(|_| DdiError::MborError(MborError::EncodeError))?,
        },
        ext: None,
    };

    let mut cookie = None;
    partition.exec_op(&req, &mut cookie)
}
