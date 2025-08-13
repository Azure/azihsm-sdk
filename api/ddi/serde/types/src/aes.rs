// Copyright (c) Microsoft Corporation. All rights reserved.

use mcr_ddi_derive::Ddi;

use crate::*;

/// DDI AES Mode Enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, PartialEq, Eq, Clone, Copy)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiAesOp {
    /// Encrypt
    Encrypt = 1,

    /// Decrypt
    Decrypt = 2,
}

/// DDI AES Key Size Enumeration
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[open_enum]
#[derive(Debug, Ddi, Copy, Eq, PartialEq, Clone)]
#[repr(u32)]
#[ddi(enumeration)]
pub enum DdiAesKeySize {
    /// AES 128-bit
    Aes128 = 1,

    /// AES 192-bit
    Aes192 = 2,

    /// AES 256-bit
    Aes256 = 3,

    /// AES Bulk 256-bit
    AesBulk256 = 4,
}

/// DDI AES Key Size Error
pub enum DdiAesKeySizeError {
    /// Invalid key size
    InvalidKeySize,
}

impl TryFrom<DdiAesKeySize> for usize {
    type Error = DdiAesKeySizeError;

    fn try_from(value: DdiAesKeySize) -> Result<Self, Self::Error> {
        match value {
            DdiAesKeySize::Aes128 => Ok(16),
            DdiAesKeySize::Aes192 => Ok(24),
            DdiAesKeySize::Aes256 => Ok(32),
            DdiAesKeySize::AesBulk256 => Ok(32),
            _ => Err(DdiAesKeySizeError::InvalidKeySize),
        }
    }
}

/// DDI AES Generate Key Request Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesGenerateKeyReq {
    /// Key size
    #[ddi(id = 1)]
    pub key_size: DdiAesKeySize,

    /// Key tag (optional). May only be used with persistent sessions.
    /// The key tag must be unique within the app.
    /// Key tag of 0x0000 is not allowed.
    #[ddi(id = 2)]
    pub key_tag: Option<u16>,

    /// Key properties
    #[ddi(id = 3)]
    pub key_properties: DdiKeyProperties,
}

/// DDI AES Generate Key Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi, Copy, Clone)]
#[ddi(map)]
pub struct DdiAesGenerateKeyResp {
    /// Key ID
    #[ddi(id = 1)]
    pub key_id: u16,

    /// Optional Bulk Key ID
    #[ddi(id = 2)]
    pub bulk_key_id: Option<u16>,

    /// Masked Key
    #[ddi(id = 3)]
    pub masked_key: MborByteArray<3072>,
}

crate::ddi_op_req_resp!(DdiAesGenerateKey);

/// Aes Encrypt Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesEncryptDecryptReq {
    #[ddi(id = 1)]
    pub key_id: u16,

    #[ddi(id = 2)]
    pub op: DdiAesOp,

    #[ddi(id = 3)]
    pub msg: MborByteArray<1024>,

    #[ddi(id = 4)]
    pub iv: MborByteArray<16>,
}

/// Aes Encrypt Response Structure
#[cfg_attr(feature = "fuzzing", derive(arbitrary::Arbitrary))]
#[derive(Debug, Ddi)]
#[ddi(map)]
pub struct DdiAesEncryptDecryptResp {
    /// Output data
    #[ddi(id = 1)]
    pub msg: MborByteArray<1024>,

    /// Initialization Vector
    #[ddi(id = 2)]
    pub iv: MborByteArray<16>,
}

crate::ddi_op_req_resp!(DdiAesEncryptDecrypt);
