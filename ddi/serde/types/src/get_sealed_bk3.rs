// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Sealed BK3 Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiGetSealedBk3Req {}

/// DDI Get Sealed BK3 Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiGetSealedBk3Resp {
    /// BK3 sealed using session encryption key
    #[ddi(id = 1)]
    pub sealed_bk3: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiGetSealedBk3);
