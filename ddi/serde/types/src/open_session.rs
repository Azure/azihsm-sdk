// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Encrypted Credential
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiEncryptedEstablishCredential {
    /// Encrypted ID
    #[ddi(id = 1)]
    pub encrypted_id: MborByteArray<16>,

    /// Encrypted PIN
    #[ddi(id = 2)]
    pub encrypted_pin: MborByteArray<16>,

    /// IV
    #[ddi(id = 3)]
    pub iv: MborByteArray<16>,

    /// Nonce from device
    #[ddi(id = 4)]
    pub nonce: [u8; 32],

    /// HMAC tag
    #[ddi(id = 5)]
    pub tag: [u8; 48],
}

/// DDI Encrypted Credential
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiEncryptedSessionCredential {
    /// Encrypted ID
    #[ddi(id = 1)]
    pub encrypted_id: MborByteArray<16>,

    /// Encrypted PIN
    #[ddi(id = 2)]
    pub encrypted_pin: MborByteArray<16>,

    /// Encrypted seed
    #[ddi(id = 3)]
    pub encrypted_seed: MborByteArray<48>,

    /// IV
    #[ddi(id = 4)]
    pub iv: MborByteArray<16>,

    /// Nonce from device
    #[ddi(id = 5)]
    pub nonce: [u8; 32],

    /// HMAC tag
    #[ddi(id = 6)]
    pub tag: [u8; 48],
}

/// DDI Open Session Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenSessionReq {
    /// Encrypted credential
    #[ddi(id = 1)]
    pub encrypted_credential: DdiEncryptedSessionCredential,

    /// Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Open Session Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiOpenSessionResp {
    /// Session ID
    #[ddi(id = 1)]
    pub sess_id: u16,

    /// Short App ID
    #[ddi(id = 2)]
    pub short_app_id: u8,

    /// Backed up Session masking key
    #[ddi(id = 3)]
    pub bmk_session: MborByteArray<1024>,
}

ddi_op_req_resp!(DdiOpenSession);
