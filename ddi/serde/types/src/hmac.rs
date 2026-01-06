// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI HMAC Function Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiHmacReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Message
    /// Maximum length 1024 bytes to match AES-CBC.
    #[ddi(id = 2)]
    pub msg: MborByteArray<1024>,
}

/// DDI HMAC Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiHmacResp {
    /// Output data
    /// HmacSha512 output = 64 bytes, HmacSha384 output = 48 bytes, HmacSha256 output = 32 bytes
    #[ddi(id = 1)]
    pub tag: MborByteArray<64>,
}

ddi_op_req_resp!(DdiHmac);
