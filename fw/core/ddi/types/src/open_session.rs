// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEncryptedEstablishCredential<'a> {
    #[ddi(id = 1, max_len = 16)]
    pub encrypted_id: &'a [u8],
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
pub struct DdiEncryptedSessionCredential<'a> {
    #[ddi(id = 1, max_len = 16)]
    pub encrypted_id: &'a [u8],
    #[ddi(id = 2, max_len = 16)]
    pub encrypted_pin: &'a [u8],
    #[ddi(id = 3, max_len = 48)]
    pub encrypted_seed: &'a [u8],
    #[ddi(id = 4, max_len = 16)]
    pub iv: &'a [u8],
    #[ddi(id = 5, len = 32)]
    pub nonce: &'a [u8],
    #[ddi(id = 6, len = 48)]
    pub tag: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenSessionReq<'a> {
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedSessionCredential<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenSessionResp<'a> {
    #[ddi(id = 1)]
    pub sess_id: u16,
    #[ddi(id = 2)]
    pub short_app_id: u8,
    #[ddi(id = 3, max_len = 1024)]
    pub bmk_session: &'a [u8],
}

ddi_op_req_resp!(DdiOpenSession, 'a);
