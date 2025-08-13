// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI Get Session Encryption Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSessionEncryptionKeyReq {}

/// DDI Get Session Encryption Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiGetSessionEncryptionKeyResp {
    /// Ecc 384 Public Key
    #[ddi(id = 1)]
    pub pub_key: DdiDerPublicKey,

    /// Nonce
    #[ddi(id = 2)]
    pub nonce: [u8; 32],

    /// Signature of the Public Key
    #[ddi(id = 3)]
    pub pub_key_signature: MborByteArray<192>,
}

ddi_op_req_resp!(DdiGetSessionEncryptionKey);
