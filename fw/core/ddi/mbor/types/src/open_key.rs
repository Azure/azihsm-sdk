// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenKeyReq {
    #[ddi(id = 1)]
    pub key_tag: u16,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenKeyResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,
    #[ddi(id = 3)]
    pub pub_key: Option<DdiPublicKey<'a>>,
    #[ddi(id = 4)]
    pub bulk_key_id: Option<u16>,
}

ddi_op_req_resp!(DdiOpenKey, resp 'a);
