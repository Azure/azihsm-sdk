// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Set Sealed BK3 Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiSetSealedBk3Req {
    /// BK3 sealed using session encryption key
    #[ddi(id = 1)]
    pub sealed_bk3: MborByteArray<1024>,
}

/// DDI Set Sealed BK3 Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiSetSealedBk3Resp {}

ddi_op_req_resp!(DdiSetSealedBk3);
