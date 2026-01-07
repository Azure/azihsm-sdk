// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Param Encryption Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiUnmaskKeyReq {
    /// Masked Key
    #[ddi(id = 1)]
    pub masked_key: MborByteArray<3072>,
}

/// DDI Get Param Encryption Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiUnmaskKeyResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional Public Key
    #[ddi(id = 2)]
    pub pub_key: Option<DdiDerPublicKey>,

    /// Optional Bulk Key ID
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,

    /// Key Type
    #[ddi(id = 4)]
    pub kind: DdiKeyType,

    /// Masked Key
    #[ddi(id = 5)]
    pub masked_key: MborByteArray<3072>,
}

ddi_op_req_resp!(DdiUnmaskKey);
