// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccGenerateKeyPairReq<'a> {
    #[ddi(id = 1)]
    pub curve: DdiEccCurve,
    #[ddi(id = 2)]
    pub key_tag: Option<u16>,
    #[ddi(id = 3)]
    pub key_properties: DdiTargetKeyProperties<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccGenerateKeyPairResp<'a> {
    #[ddi(id = 1)]
    pub private_key_id: u16,
    #[ddi(id = 2, frame)]
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 3, max_len = 3072)]
    pub masked_key: &'a [u8],
}

ddi_op_req_resp!(DdiEccGenerateKeyPair, 'a);
