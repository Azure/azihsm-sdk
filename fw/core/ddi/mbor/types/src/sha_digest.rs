// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiShaDigestReq<'a> {
    #[ddi(id = 1)]
    pub sha_mode: DdiHashAlgorithm,
    #[ddi(id = 2, max_len = 1024)]
    pub msg: &'a DmaBuf,
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiShaDigestResp<'a> {
    #[ddi(id = 1, max_len = 64)]
    pub digest: &'a [u8],
}

ddi_op_req_resp!(DdiShaDigest, 'a);
