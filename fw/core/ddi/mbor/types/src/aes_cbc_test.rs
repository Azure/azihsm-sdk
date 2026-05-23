// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesCbcTestReq<'a> {
    #[ddi(id = 1, max_len = 32)]
    pub key: &'a [u8],
    #[ddi(id = 2, max_len = 16)]
    pub iv: &'a [u8],
    #[ddi(id = 3, max_len = 4096)]
    pub data: &'a [u8],
    #[ddi(id = 4)]
    pub encrypt: bool,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesCbcTestResp<'a> {
    #[ddi(id = 1, max_len = 4096)]
    pub result: &'a [u8],
    #[ddi(id = 2, max_len = 16)]
    pub iv_out: &'a [u8],
}

ddi_op_req_resp!(DdiAesCbcTest, 'a);
