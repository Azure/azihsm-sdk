// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI Open Session Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiReopenSessionReq {
    /// Encrypted credential
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedCredential,

    /// Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Open Session Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiReopenSessionResp {
    /// Session ID
    #[ddi(id = 1)]
    pub sess_id: u16,

    /// Short App ID
    #[ddi(id = 2)]
    pub short_app_id: u8,
}

ddi_op_req_resp!(DdiReopenSession);
