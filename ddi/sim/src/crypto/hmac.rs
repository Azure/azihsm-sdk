// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for describing keys used for Hash operations

use crate::crypto::sha;
use crate::crypto::sha::HashAlgorithm;
use crate::errors::ManticoreError;
use crate::mask::KeySerialization;
use crate::table::entry::Kind;

/// Trait for Hmac hash operations
pub trait HmacOp {
    /// Create an `HmacKey` instance from array of bits,
    ///
    /// # Arguments
    /// * `bytes` - Array of bits
    ///
    /// # Returns
    /// * `HmacKey` - The created instance.
    ///
    /// # Errors
    /// * `ManticoreError::InvalidArgument` - If the raw data has invalid size.
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError>
    where
        Self: Sized;

    /// Use Hmac operaiton
    fn hmac(&self, bytes: &[u8], hash_algo: HashAlgorithm) -> Result<Vec<u8>, ManticoreError>;
}

/// Supported Hmac sizes
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum HmacShaSize {
    /// 256-bit key using Sha-256
    HmacSha256,

    /// 384-bit key using Sha-384
    HmacSha384,

    /// 512-bit key using Sha-512
    HmacSha512,
}

/// HmacKey is a key used for Hmac operations
#[derive(Debug, Clone)]
pub struct HmacKey {
    key: Vec<u8>,
}

impl KeySerialization<HmacKey> for HmacKey {
    fn serialize(&self) -> Result<Vec<u8>, ManticoreError> {
        Ok(self.key.clone())
    }

    fn deserialize(raw: &[u8], expected_type: Kind) -> Result<HmacKey, ManticoreError> {
        match expected_type {
            Kind::HmacSha256 | Kind::HmacSha384 | Kind::HmacSha512 => HmacKey::from_bytes(raw),
            _ => {
                tracing::error!(error=?ManticoreError::DerAndKeyTypeMismatch, ?expected_type, "Expected type should be HMAC when deserializing masked key for HmacKey");
                Err(ManticoreError::DerAndKeyTypeMismatch)
            }
        }
    }
}

impl HmacOp for HmacKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ManticoreError> {
        Ok(Self {
            key: bytes.to_vec(),
        })
    }

    fn hmac(&self, msg: &[u8], hash_algorithm: HashAlgorithm) -> Result<Vec<u8>, ManticoreError> {
        // L = Hash output length (bytes)
        let sha_digest_size = hash_algorithm.digest_size();

        // B = data block length used by hash function (bytes)
        let sha_block_size = hash_algorithm.block_size();

        let mut key_block = vec![0u8; sha_block_size];

        let key = self.key.as_slice();

        // Applications that use keys longer
        // than B bytes will first hash the key using H and then use the
        // resultant L byte string as the actual key to HMAC.
        if key.len() > sha_block_size {
            // Hash the key if it is longer than the block size
            let out_buf = sha::sha(hash_algorithm, key)?;
            key_block[..sha_digest_size].copy_from_slice(&out_buf);
        } else {
            // Copy the key into the block
            key_block[..key.len()].copy_from_slice(key);
        }

        // Create the IPAD and OPAD values
        let mut ipad = vec![0x36; sha_block_size];
        let mut opad = vec![0x5C; sha_block_size];

        for i in 0..sha_block_size {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut in_buf = Vec::new();

        // (K XOR ipad, text)
        in_buf.extend_from_slice(&ipad);
        in_buf.extend_from_slice(msg);

        // H(K XOR ipad, text)
        let out_buf = sha::sha(hash_algorithm, in_buf.as_slice())?;

        // (K XOR opad, H(K XOR ipad, text))
        in_buf.clear();
        in_buf.extend_from_slice(&opad);
        in_buf.extend_from_slice(&out_buf);

        // H(K XOR opad, H(K XOR ipad, text))
        sha::sha(hash_algorithm, in_buf.as_slice())
    }
}

#[test]
fn test_hmac_sha_256() {
    let mut key: [u8; 32] = [2u8; 32];
    let mut data: [u8; 1024] = [1u8; 1024];

    let hmac_key1 = HmacKey::from_bytes(&key).unwrap();
    let result = hmac_key1.hmac(&data, HashAlgorithm::Sha256);
    assert!(result.is_ok());
    let sig1 = result.unwrap();

    let hmac_key2 = HmacKey::from_bytes(&key).unwrap();
    let result = hmac_key2.hmac(&data, HashAlgorithm::Sha256);
    assert!(result.is_ok());
    let sig2 = result.unwrap();

    // Modify data
    data[512] = !data[512];
    let result = hmac_key1.hmac(&data, HashAlgorithm::Sha256);
    assert!(result.is_ok());
    let sig3 = result.unwrap();
    data[512] = !data[512];

    // Modify key
    key[16] = !key[16];
    let hmac_key2 = HmacKey::from_bytes(&key).unwrap();
    let result = hmac_key2.hmac(&data, HashAlgorithm::Sha256);
    assert!(result.is_ok());
    let sig4 = result.unwrap();
    key[16] = !key[16];

    // Modify both key and data
    data[512] = !data[512];
    key[16] = !key[16];
    let hmac_key3 = HmacKey::from_bytes(&key).unwrap();
    let result = hmac_key3.hmac(&data, HashAlgorithm::Sha256);
    assert!(result.is_ok());
    let sig5 = result.unwrap();
    data[512] = !data[512];
    key[16] = !key[16];

    // Check signatures
    assert_eq!(sig1, sig2);

    assert_ne!(sig1, sig3);
    assert_ne!(sig1, sig4);
    assert_ne!(sig1, sig5);

    assert_ne!(sig3, sig4);
    assert_ne!(sig4, sig5);
}
