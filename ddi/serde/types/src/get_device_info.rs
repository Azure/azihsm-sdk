// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI Get Device Info Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetDeviceInfoReq {}

/// DDI Get Device Info Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetDeviceInfoResp {
    /// Device Kind
    #[ddi(id = 1)]
    pub kind: DdiDeviceKind,

    /// Number of tables assigned to the device
    #[ddi(id = 2)]
    pub tables: u8,

    /// Module's FIPS approval status
    #[ddi(id = 3)]
    pub fips_approved: bool,
}
crate::ddi_op_req_resp!(DdiGetDeviceInfo);
