// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiCloseSessionReq {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiCloseSessionResp {}

ddi_op_req_resp!(DdiCloseSession);
