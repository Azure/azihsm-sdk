// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;
use crate::crypto::aes::AES_XTS_SECTOR_NUM_LEN;

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

pub(crate) fn aes_xts_enc_dec(
    partition: &<HsmDdi as Ddi>::Dev,
    sess_id: u16,
    short_app_id: u8,
    key_id1: u16,
    key_id2: u16,
    op: DdiAesOp,
    input: &[u8],
    tweak: [u8; AES_XTS_SECTOR_NUM_LEN],
    data_unit_len: u32,
) -> Result<DdiAesXtsResult, DdiError> {
    let mcr_fp_xts_params = DdiAesXtsParams {
        key_id1: key_id1 as u32,
        key_id2: key_id2 as u32,
        session_id: sess_id,
        short_app_id,
        tweak,
        data_unit_len: data_unit_len as usize,
    };

    partition.exec_op_fp_xts(op, mcr_fp_xts_params, input.to_vec())
}
