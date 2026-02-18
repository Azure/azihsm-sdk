// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Initialize BK3 Request Structure
/// BK3 is a 48-byte secret key used as the 'key' input to the KDF
/// BKS1 and BKS2 are the seeds that are used as the 'context' input to the KDF
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiInitBk3Req {
    /// BK3
    #[ddi(id = 1)]
    pub bk3: MborByteArray<48>,
}

/// DDI Initialize BK3 Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Ddi, Debug)]
#[ddi(map)]
pub struct DdiInitBk3Resp {
    /// Output data (masked BK3)
    #[ddi(id = 1)]
    pub masked_bk3: MborByteArray<1024>,

    /// Launch ID for the partition
    #[ddi(id = 2)]
    pub vm_launch_guid: [u8; 16],
}

ddi_op_req_resp!(DdiInitBk3);
