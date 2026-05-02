// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

/// Error Request Structure
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiErrReq {}

/// Error Response Structure
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiErrResp {}

ddi_op_req_resp!(DdiErr);
