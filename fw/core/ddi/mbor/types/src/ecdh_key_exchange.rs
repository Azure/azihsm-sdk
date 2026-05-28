// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEcdhKeyExchangeReq<'a> {
    #[ddi(id = 1)]
    pub priv_key_id: u16,
    #[ddi(id = 2, max_len = 192)]
    pub pub_key_der: &'a DmaBuf,
    #[ddi(id = 3)]
    pub key_type: DdiKeyType,
    #[ddi(id = 4)]
    pub key_tag: Option<u16>,
    #[ddi(id = 5)]
    pub key_properties: DdiTargetKeyProperties<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEcdhKeyExchangeResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 3072)]
    pub masked_key: &'a [u8],
}

ddi_op_req_resp!(DdiEcdhKeyExchange, 'a);
