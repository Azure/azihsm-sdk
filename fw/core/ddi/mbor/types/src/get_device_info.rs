// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetDeviceInfoReq {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetDeviceInfoResp {
    #[ddi(id = 1)]
    pub kind: DdiDeviceKind,
    #[ddi(id = 2)]
    pub tables: u8,
    #[ddi(id = 3)]
    pub fips_approved: bool,
}

ddi_op_req_resp!(DdiGetDeviceInfo);
