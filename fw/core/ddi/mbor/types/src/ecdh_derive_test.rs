// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! D-PKA-3: NoSession test DDI for ECDH out-of-session derive
//! validation. Mirrors the `EccVerifyTest` D-PKA-2 pattern. Wire
//! format is engine-native little-endian:
//!
//!   Req:  { curve, priv_key (LE scalar), peer_pub_key (LE X || Y) }
//!   Resp: { secret (LE X coord) }   // ECDH shared secret X coord only
//!
//! Curves: P-256, P-384, P-521 (D-PKA-2b/3b).

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEcdhDeriveTestReq<'a> {
    #[ddi(id = 1)]
    pub curve: DdiEccCurve,
    #[ddi(id = 2, max_len = 132)]
    pub priv_key: &'a [u8],
    #[ddi(id = 3, max_len = 136)]
    pub peer_pub_key: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEcdhDeriveTestResp<'a> {
    #[ddi(id = 1, max_len = 132)]
    pub secret: &'a [u8],
}

ddi_op_req_resp!(DdiEcdhDeriveTest, 'a);
