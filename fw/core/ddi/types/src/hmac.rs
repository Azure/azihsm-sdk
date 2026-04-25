// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiHmacReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 1024)]
    pub msg: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiHmacResp<'a> {
    #[ddi(id = 1, max_len = 64)]
    pub tag: &'a [u8],
}

ddi_op_req_resp!(DdiHmac, 'a);
