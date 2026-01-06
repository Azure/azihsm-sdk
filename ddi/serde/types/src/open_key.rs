// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Open Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenKeyReq {
    /// Key tag
    #[ddi(id = 1)]
    pub key_tag: u16,
}

/// DDI Open Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenKeyResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Key type
    #[ddi(id = 2)]
    pub key_kind: DdiKeyType,

    /// Optional public key
    #[ddi(id = 3)]
    pub pub_key: Option<DdiDerPublicKey>,

    /// Optional Bulk Key ID
    #[ddi(id = 4)]
    pub bulk_key_id: Option<u16>,
}

ddi_op_req_resp!(DdiOpenKey);
