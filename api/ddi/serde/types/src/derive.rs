// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI HKDF Derive Function Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiHkdfDeriveReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Hash algorithm
    #[ddi(id = 2)]
    pub hash_algorithm: DdiHashAlgorithm,

    /// Salt
    #[ddi(id = 3)]
    pub salt: Option<MborByteArray<256>>,

    /// Info
    #[ddi(id = 4)]
    pub info: Option<MborByteArray<256>>,

    /// Target key type
    #[ddi(id = 5)]
    pub key_type: DdiKeyType,

    /// Target key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 6)]
    pub key_tag: Option<u16>,

    /// Target key properties
    #[ddi(id = 7)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI HKDF Derive Function Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[ddi(map)]
pub struct DdiHkdfDeriveResp {
    /// Derived AES key
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Masked Key
    #[ddi(id = 2)]
    pub masked_key: MborByteArray<3072>,

    /// Optional Bulk Key ID
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,
}

ddi_op_req_resp!(DdiHkdfDerive);

/// DDI KBKDF Counter HMAC Derive Function Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiKbkdfCounterHmacDeriveReq {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Hash algorithm
    #[ddi(id = 2)]
    pub hash_algorithm: DdiHashAlgorithm,

    /// Label
    #[ddi(id = 3)]
    pub label: Option<MborByteArray<256>>,

    /// Context
    #[ddi(id = 4)]
    pub context: Option<MborByteArray<256>>,

    /// Target key type
    #[ddi(id = 5)]
    pub key_type: DdiKeyType,

    /// Target key tag (optional). May only be used with app keys.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 6)]
    pub key_tag: Option<u16>,

    /// Target key properties
    #[ddi(id = 7)]
    pub key_properties: DdiTargetKeyProperties,
}

/// DDI KBKDF Counter HMAC Derive Function Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiKbkdfCounterHmacDeriveResp {
    /// Derived AES key
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Masked Key
    #[ddi(id = 2)]
    pub masked_key: MborByteArray<3072>,

    /// Optional Bulk Key ID
    #[ddi(id = 3)]
    pub bulk_key_id: Option<u16>,
}

ddi_op_req_resp!(DdiKbkdfCounterHmacDerive);
