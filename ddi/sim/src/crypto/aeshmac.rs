// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for AesHmac keys, which is only used for Sealing Key.

use super::aes::AesAlgo;
use super::aes::AesDecryptResult;
use super::aes::AesEncryptResult;
use crate::crypto::aes::AesKey;
use crate::crypto::aes::AesOp;
use crate::crypto::sha::hmac_sha_384;
use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

/// Supported AES Key size.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AesHmacKeySize {
    /// 640-bit key.
    /// First 256-bit is used for AES Encrypt/Decrypt
    /// Last 384-bit is used for HMAC SHA384 Operation
    AesHmac640,
}

/// AES + HMAC Key.
#[derive(Debug, Clone)]
pub struct AesHmacKey {
    key: Vec<u8>,
    #[allow(unused)]
    size: AesHmacKeySize,
}

/// Trait for Aes HMAC operations
pub trait AesHmacOp {
    /// Create a new instance of `AesHmacKey` from raw bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError>
    where
        Self: Sized;

    /// AES CBC Encrypt data using the first 256 bits of the key.
    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, ManticoreError>;

    /// AES CBC Decrypt data using the first 256 bits of the key.
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, ManticoreError>;

    /// HMAC-SHA-384 operation using the last 384 bits of the key.
    fn hmac_sha_384(&self, data: &[u8]) -> Result<[u8; 48], ManticoreError>;
}

impl AesHmacOp for AesHmacKey {
    /// Create a `AesHmacKey` instance from array of bits,
    ///
    /// # Arguments
    /// * `bytes` - Array of bits
    ///
    /// # Returns
    /// * `AesHmacKey` - The created instance.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the raw data has invalid size.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError> {
        let size = match bytes.len() {
            80 => AesHmacKeySize::AesHmac640,
            invalid_bytes_len => {
                tracing::error!(invalid_bytes_len, "Invalid AesHmacKey size");
                Err(ManticoreError::InvalidArgument)?
            }
        };

        Ok(Self {
            key: bytes.to_vec(),
            size,
        })
    }

    /// AES encryption using the first 256 bit.
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted.
    /// * `algo` - AES algo (CBC or GCM).
    /// * `iv` - The IV value.
    ///
    /// # Returns
    /// * `AesEncryptResult` - The encryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesEncryptError` - If the encryption fails.
    fn encrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesEncryptResult, ManticoreError> {
        let aes_key = AesKey::from_bytes(&self.key[..32])?;

        aes_key.encrypt(data, algo, iv)
    }

    /// AES decryption using the first 256 bit.
    ///
    /// # Arguments
    /// * `data` - The data to be decrypted.
    /// * `algo` - AES algo (CBC).
    /// * `iv` - The IV value.
    ///
    /// # Returns
    /// * `AesDecryptResult` - The decryption result.
    ///
    /// # Errors
    /// * `ManticoreError::AesDecryptError` - If the decryption fails.
    fn decrypt(
        &self,
        data: &[u8],
        algo: AesAlgo,
        iv: Option<&[u8]>,
    ) -> Result<AesDecryptResult, ManticoreError> {
        let aes_key = AesKey::from_bytes(&self.key[..32])?;

        aes_key.decrypt(data, algo, iv)
    }

    /// HMAC-SHA-384 operation using the last 384 bits of the key.
    ///
    /// # Arguments
    /// * `data` - The data to be hashed.
    ///
    /// # Returns
    /// * `[u8; 48]` - The resulting hash.
    ///
    /// # Errors
    /// * `ManticoreError::HmacError` - If the HMAC operation fails.
    fn hmac_sha_384(&self, data: &[u8]) -> Result<[u8; 48], ManticoreError> {
        hmac_sha_384(&self.key[32..80], data)
    }
}

impl KeySerialization<AesHmacKey> for AesHmacKey {
    /// Serialize the AesHmacKey to bytes
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        Ok(self.key.clone())
    }

    /// Deserialize bytes to AesHmacKey
    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<AesHmacKey, ManticoreError> {
        match expected_type {
            Kind::AesHmac640 => AesHmacKey::from_bytes(raw),
            _ => {
                tracing::error!(error=?ManticoreError::DerAndKeyTypeMismatch, ?expected_type, "Expected type should be AesHmac640 when deserializing AesHmacKey");
                Err(ManticoreError::DerAndKeyTypeMismatch)
            }
        }
    }
}
