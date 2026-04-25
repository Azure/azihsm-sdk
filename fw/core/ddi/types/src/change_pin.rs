// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEncryptedPin<'a> {
    #[ddi(id = 2, max_len = 16)]
    pub encrypted_pin: &'a [u8],
    #[ddi(id = 3, max_len = 16)]
    pub iv: &'a [u8],
    #[ddi(id = 4, len = 32)]
    pub nonce: &'a [u8],
    #[ddi(id = 5, len = 48)]
    pub tag: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiChangePinReq<'a> {
    #[ddi(id = 1)]
    pub new_pin: DdiEncryptedPin<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiChangePinResp {}

ddi_op_req_resp!(DdiChangePin, req 'a);
