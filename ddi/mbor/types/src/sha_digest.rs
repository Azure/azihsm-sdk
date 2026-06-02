// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_mbor_derive::Ddi;

use crate::*;

/// DDI SHA Digest Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiShaDigestReq {
    /// Hash algorithm to use
    #[ddi(id = 1)]
    pub sha_mode: DdiHashAlgorithm,

    /// Message to hash
    /// Maximum length 1024 bytes.
    #[ddi(id = 2)]
    pub msg: MborByteArray<1024>,
}

/// DDI SHA Digest Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone)]
#[ddi(map)]
pub struct DdiShaDigestResp {
    /// Output digest
    /// SHA-512 output = 64 bytes (max)
    #[ddi(id = 1)]
    pub digest: MborByteArray<64>,
}

ddi_op_req_resp!(DdiShaDigest);
