// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiKbkdfCounterHmacDeriveReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2)]
    pub hash_algorithm: DdiHashAlgorithm,
    #[ddi(id = 3, max_len = 256)]
    pub label: Option<&'a DmaBuf>,
    #[ddi(id = 4, max_len = 256)]
    pub context: Option<&'a DmaBuf>,
    #[ddi(id = 5)]
    pub key_type: DdiKeyType,
    #[ddi(id = 6)]
    pub key_tag: Option<u16>,
    #[ddi(id = 7)]
    pub key_properties: DdiTargetKeyProperties<'a>,
    #[ddi(id = 8)]
    pub key_length: Option<u8>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiKbkdfCounterHmacDeriveResp<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 3072)]
    pub masked_key: &'a [u8],
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,
}

ddi_op_req_resp!(DdiKbkdfCounterHmacDerive, 'a);
