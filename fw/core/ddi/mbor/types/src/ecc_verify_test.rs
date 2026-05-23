// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! D-PKA-2: NoSession test DDI for ECC verify out-of-session
//! validation. Mirrors the `EccSign` (NoSession-bypassed) test op
//! pattern from K5. Wire format:
//!
//!   Req:  { curve, pub_key (BE X || Y), digest (BE), signature (BE r || s) }
//!   Resp: { valid: u8 }   // 1 = signature valid, 0 = invalid
//!
//! Curves: P-256, P-384, P-521 (D-PKA-2b/3b).

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccVerifyTestReq<'a> {
    #[ddi(id = 1)]
    pub curve: DdiEccCurve,
    #[ddi(id = 2, max_len = 136)]
    pub pub_key: &'a [u8],
    #[ddi(id = 3, max_len = 96)]
    pub digest: &'a [u8],
    #[ddi(id = 4, max_len = 136)]
    pub signature: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEccVerifyTestResp {
    #[ddi(id = 1)]
    pub valid: u8,
}

ddi_op_req_resp!(DdiEccVerifyTest, req 'a);
