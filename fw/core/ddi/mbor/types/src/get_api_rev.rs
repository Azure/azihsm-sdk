// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetApiRevReq {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetApiRevResp {
    #[ddi(id = 1)]
    pub min: DdiApiRev,
    #[ddi(id = 2)]
    pub max: DdiApiRev,
}

ddi_op_req_resp!(DdiGetApiRev);
