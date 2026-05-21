// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAttestKeyReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 128)]
    pub report_data: &'a DmaBuf,
}

impl DdiAttestKeyReq<'_> {
    pub const MAX_REPORT_DATA_SIZE: usize = 128;
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAttestKeyResp<'a> {
    #[ddi(id = 1, max_len = 834)]
    pub report: &'a [u8],
}

impl DdiAttestKeyResp<'_> {
    pub const MAX_REPORT_SIZE: usize = 834;
}

ddi_op_req_resp!(DdiAttestKey, 'a);
