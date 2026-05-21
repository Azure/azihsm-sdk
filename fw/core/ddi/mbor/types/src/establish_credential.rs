// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::open_session::DdiEncryptedEstablishCredential;
use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialReq<'a> {
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedEstablishCredential<'a>,
    #[ddi(id = 2)]
    pub pub_key: DdiPublicKey<'a>,
    #[ddi(id = 3, max_len = 1024)]
    pub masked_bk3: &'a DmaBuf,
    #[ddi(id = 4, max_len = 1024)]
    pub bmk: &'a DmaBuf,
    #[ddi(id = 5, max_len = 1024)]
    pub masked_unwrapping_key: &'a DmaBuf,
    #[ddi(id = 6, max_len = 1024)]
    pub pota_sig: &'a DmaBuf,
    #[ddi(id = 7)]
    pub pota_pub_key: DdiPublicKey<'a>,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialResp<'a> {
    #[ddi(id = 1, max_len = 1024)]
    pub bmk: &'a [u8],
}

ddi_op_req_resp!(DdiEstablishCredential, 'a);
