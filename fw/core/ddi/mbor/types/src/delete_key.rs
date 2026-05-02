// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiDeleteKeyReq {
    #[ddi(id = 1)]
    pub key_id: u16,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiDeleteKeyResp {}

ddi_op_req_resp!(DdiDeleteKey);
