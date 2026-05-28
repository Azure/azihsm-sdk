// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertChainInfoReq {
    #[ddi(id = 1)]
    pub slot_id: u8,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertChainInfoResp<'a> {
    #[ddi(id = 1)]
    pub num_certs: u8,
    #[ddi(id = 2, max_len = 32)]
    pub thumbprint: &'a [u8],
}

ddi_op_req_resp!(DdiGetCertChainInfo, resp 'a);
