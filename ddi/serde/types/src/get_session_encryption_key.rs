// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

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
    #[ddi(post_decode_fn = "signature_post_decode")]
    pub pub_key_signature: MborByteArray<192>,
}

impl DdiGetSessionEncryptionKeyResp {
    #[cfg(feature = "post_decode")]
    pub fn signature_post_decode(
        &self,
        input_array: &MborByteArray<192>,
    ) -> Result<MborByteArray<192>, MborDecodeError> {
        ecc_signature_post_decode(input_array)
    }
}

ddi_op_req_resp!(DdiGetSessionEncryptionKey);
