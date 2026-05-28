// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::open_session::DdiEncryptedSessionCredential;
use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiReopenSessionReq<'a> {
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedSessionCredential<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 3, max_len = 1024)]
    pub bmk_session: &'a DmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiReopenSessionResp<'a> {
    #[ddi(id = 1)]
    pub sess_id: u16,
    #[ddi(id = 2)]
    pub short_app_id: u8,
    #[ddi(id = 3, max_len = 1024)]
    pub bmk_session: &'a [u8],
}

ddi_op_req_resp!(DdiReopenSession, 'a);
