// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEncryptedEstablishCredential<'a> {
    #[ddi(id = 1, len = 16)]
    pub encrypted_id: &'a mut DmaBuf,
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
pub struct DdiEncryptedSessionCredential<'a> {
    #[ddi(id = 1, len = 16)]
    pub encrypted_id: &'a mut DmaBuf,
    #[ddi(id = 2, len = 16)]
    pub encrypted_pin: &'a mut DmaBuf,
    #[ddi(id = 3, len = 48)]
    pub encrypted_seed: &'a mut DmaBuf,
    #[ddi(id = 4, len = 16)]
    pub iv: &'a mut DmaBuf,
    #[ddi(id = 5, len = 32)]
    pub nonce: &'a mut DmaBuf,
    #[ddi(id = 6, len = 48)]
    pub tag: &'a mut DmaBuf,
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
