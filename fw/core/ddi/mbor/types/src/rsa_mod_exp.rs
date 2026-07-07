// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaModExpReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 512)]
    pub y: &'a mut DmaBuf,
    #[ddi(id = 3)]
    pub op_type: DdiRsaOpType,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaModExpResp<'a> {
    #[ddi(id = 1, max_len = 512)]
    pub x: &'a [u8],
}

ddi_op_req_resp!(DdiRsaModExp, 'a);
