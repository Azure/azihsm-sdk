// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetUnwrappingKeyReq {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetUnwrappingKeyResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 3, max_len = 1024)]
    pub masked_key: &'a [u8],
}

ddi_op_req_resp!(DdiGetUnwrappingKey, resp 'a);
