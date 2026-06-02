// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSealedBk3Req {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSealedBk3Resp<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub sealed_bk3: &'a [u8],
}

ddi_op_req_resp!(DdiGetSealedBk3, resp 'a);
