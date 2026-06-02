// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSessionEncryptionKeyReq {}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSessionEncryptionKeyResp<'a> {
    #[ddi(id = 1, frame)]
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 2, len = 32)]
    pub nonce: &'a [u8],
    #[ddi(id = 3, max_len = 192)]
    pub pub_key_signature: &'a [u8],
}

ddi_op_req_resp!(DdiGetSessionEncryptionKey, resp 'a);
