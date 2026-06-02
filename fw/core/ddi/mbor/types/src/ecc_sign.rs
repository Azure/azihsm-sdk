// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccSignReq<'a> {
    #[ddi(id = 1)]
    pub key_id: u16,
    #[ddi(id = 2, max_len = 96)]
    pub digest: &'a mut DmaBuf,
    #[ddi(id = 3)]
    pub digest_algo: DdiHashAlgorithm,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccSignResp<'a> {
    #[ddi(id = 1, max_len = 192)]
    pub signature: &'a [u8],
}

ddi_op_req_resp!(DdiEccSign, 'a);
