// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertificateReq {
    #[ddi(id = 1)]
    pub slot_id: u8,
    #[ddi(id = 2)]
    pub cert_id: u8,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetCertificateResp<'a> {
    #[ddi(id = 1, max_len = 2048)]
    pub certificate: &'a [u8],
}

ddi_op_req_resp!(DdiGetCertificate, resp 'a);
