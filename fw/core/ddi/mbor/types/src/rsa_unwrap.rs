// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaUnwrapReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 3072)]
    pub wrapped_blob: &'a DmaBuf,
    #[ddi(id = 3)]
    pub wrapped_blob_key_class: DdiKeyClass,
    #[ddi(id = 4)]
    pub wrapped_blob_padding: DdiRsaCryptoPadding,
    #[ddi(id = 5)]
    pub wrapped_blob_hash_algorithm: DdiHashAlgorithm,
    #[ddi(id = 6)]
    pub key_tag: Option<u16>,
    #[ddi(id = 7)]
    pub key_properties: DdiTargetKeyProperties<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaUnwrapResp<'a> {
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

ddi_op_req_resp!(DdiRsaUnwrap, 'a);
