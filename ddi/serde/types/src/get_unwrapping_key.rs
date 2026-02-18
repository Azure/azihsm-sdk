// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Get Unwrapping Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetUnwrappingKeyReq {}

/// DDI Get Unwrapping Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetUnwrappingKeyResp {
    /// Private key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Public Key
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,

    /// Masked Key
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiGetUnwrappingKey);
