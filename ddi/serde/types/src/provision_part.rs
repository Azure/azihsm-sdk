// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Provision Partition Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiProvisionPartReq {
    /// Masked BK3
    #[ddi(id = 1)]
    pub masked_bk3: MborByteArray<1024>,

    /// Backed up Masked Key, if available
    #[ddi(id = 2)]
    pub bmk: MborByteArray<1024>,
}

/// DDI Provision Partition Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiProvisionPartResp {
    /// Backed up Masked Key, if not provided in the request.
    #[ddi(id = 1)]
    pub bmk: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiProvisionPart);
