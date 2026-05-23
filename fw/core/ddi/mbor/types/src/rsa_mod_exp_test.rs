// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! D-PKA-4: NoSession test DDI for RSA `mod_exp` out-of-session
//! validation. Parallels the D-PKA-2 EccVerifyTest and D-PKA-3
//! EcdhDeriveTest patterns. Wire format is engine-native LE:
//!
//!   Req:  { size, op_kind, key (exp||N, LE), input (LE) }
//!   Resp: { output (LE) }
//!
//! Sizes (v1): RSA-2K only. RSA-3K / RSA-4K return UnsupportedCmd.
//! Op kinds: Pub (`y^e mod N`) and Priv (`y^d mod N`, non-CRT raw).

use azihsm_fw_ddi_mbor_derive::Ddi;

use crate::*;

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaModExpTestReq<'a> {
    #[ddi(id = 1)]
    pub size: DdiRsaSize,
    #[ddi(id = 2)]
    pub op_kind: DdiRsaOpKind,
    /// `e || N` (Pub) or `d || N` (Priv), both LE, each
    /// `modulus_bytes(size)` long. Total len = `2 * modulus_bytes(size)`.
    #[ddi(id = 3, max_len = 1024)]
    pub key: &'a [u8],
    /// Input `y`, LE, length = `modulus_bytes(size)`.
    #[ddi(id = 4, max_len = 512)]
    pub input: &'a [u8],
}

#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiRsaModExpTestResp<'a> {
    /// Output `y^exp mod N`, LE, length = `modulus_bytes(size)`.
    #[ddi(id = 1, max_len = 512)]
    pub output: &'a [u8],
}

ddi_op_req_resp!(DdiRsaModExpTest, 'a);
