// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEncryptedPin<'a> {
    #[ddi(id = 2, len = 16)]
    pub encrypted_pin: &'a mut DmaBuf,
    #[ddi(id = 3, len = 16)]
    pub iv: &'a mut DmaBuf,
    #[ddi(id = 4, len = 32)]
    pub nonce: &'a mut DmaBuf,
    #[ddi(id = 5, len = 48)]
    pub tag: &'a mut DmaBuf,
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
