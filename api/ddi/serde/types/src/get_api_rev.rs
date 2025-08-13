// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// Get API Revision Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetApiRevReq {}

/// Get API Revision Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetApiRevResp {
    /// Minimum API revision supported
    #[ddi(id = 1)]
    pub min: DdiApiRev,

    /// Maximum API revision supported
    #[ddi(id = 2)]
    pub max: DdiApiRev,
}

crate::ddi_op_req_resp!(DdiGetApiRev);
