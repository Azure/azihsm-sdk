// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesEncryptDecryptReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub op: DdiAesOp,
    #[ddi(id = 3, max_len = 1024)]
    pub msg: &'a mut DmaBuf,
    #[ddi(id = 4, max_len = 16)]
    pub iv: &'a mut DmaBuf,
}

impl DdiAesEncryptDecryptReq<'_> {
    pub const MAX_MSG_SIZE: usize = 1024;
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesEncryptDecryptResp<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub msg: &'a [u8],
    #[ddi(id = 2, max_len = 16)]
    pub iv: &'a [u8],
}

ddi_op_req_resp!(DdiAesEncryptDecrypt, 'a);
