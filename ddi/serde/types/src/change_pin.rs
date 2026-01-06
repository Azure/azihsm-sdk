// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi_derive::Ddi;

use crate::*;

/// DDI Encrypted PIN
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Clone, PartialEq, Eq)]
#[ddi(map)]
pub struct DdiEncryptedPin {
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

/// DDI Change Pin Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiChangePinReq {
    /// New Pin (Encrypted)
    #[ddi(id = 1)]
    pub new_pin: DdiEncryptedPin,

    /// Client Public Key (ECC 384)
    #[ddi(id = 2)]
    pub pub_key: DdiDerPublicKey,
}

/// DDI Change PIN Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiChangePinResp {}

ddi_op_req_resp!(DdiChangePin);
