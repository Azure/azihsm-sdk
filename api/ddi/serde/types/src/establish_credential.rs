// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI Get Param Encryption Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialReq {
    /// Encrypted credential
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedCredential,

    /// Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Get Param Encryption Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiEstablishCredentialResp {}

ddi_op_req_resp!(DdiEstablishCredential);
