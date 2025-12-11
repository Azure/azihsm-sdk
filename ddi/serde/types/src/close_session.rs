// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// Close Session Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiCloseSessionReq {}

/// Close App Session Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiCloseSessionResp {}

crate::ddi_op_req_resp!(DdiCloseSession);
