// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetSealedBk3Req<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub sealed_bk3: &'a mut DmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiSetSealedBk3Resp {}

ddi_op_req_resp!(DdiSetSealedBk3, req 'a);
