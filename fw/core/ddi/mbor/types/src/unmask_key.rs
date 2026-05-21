// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiUnmaskKeyReq<'a> {
    #[ddi(id = 1, max_len = 3072)]
    pub masked_key: &'a DmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiUnmaskKeyResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub pub_key: Option<DdiPublicKey<'a>>,
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,
    #[ddi(id = 4)]
    pub kind: DdiKeyType,
    #[ddi(id = 5, max_len = 3072)]
    pub masked_key: &'a [u8],
}

ddi_op_req_resp!(DdiUnmaskKey, 'a);
