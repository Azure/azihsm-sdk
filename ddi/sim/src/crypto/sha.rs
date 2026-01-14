// Copyright (C) Microsoft Corporation. All rights reserved.

//! Module for SHA.

use azihsm_crypto::DeriveOp;
use azihsm_crypto::ExportableKey;
use azihsm_crypto::GenericSecretKey;
use azihsm_crypto::HashAlgo;
use azihsm_crypto::HashOp;
use azihsm_crypto::HkdfAlgo;
use azihsm_crypto::HkdfMode;
use azihsm_crypto::HmacAlgo;
use azihsm_crypto::HmacKey;
use azihsm_crypto::ImportableKey;
use azihsm_crypto::SignOp;

use crate::errors::ManticoreError;

/// Supported hash algorithms (only SHA for now).
#[derive(Clone, Copy, PartialEq)]
pub enum HashAlgorithm {
    /// SHA-1
    Sha1,

    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,
}

impl HashAlgorithm {
    /// Returns the size of the hash in bytes.
    pub fn digest_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }

    /// Returns the block size of the hash algorithm.
    pub fn block_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 64,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha384 => 128,
            HashAlgorithm::Sha512 => 128,
        }
    }
}

///  SHA operation.
///
/// # Arguments
/// * `hash_algorithm` - The SHA algorithm (SHA-1/ SHA-256/ SHA-384/ SHA-512) to be used.
/// * `data` - The data to be hashed.
///
/// # Returns
/// * `Vec<u8>` - The resulting hash.
///
/// # Errors
/// * `ManticoreError::ShaError` - If the SHA operation fails.
pub(crate) fn sha(hash_algorithm: HashAlgorithm, data: &[u8]) -> Result<Vec<u8>, ManticoreError> {
    let mut hash_algo = match hash_algorithm {
        HashAlgorithm::Sha1 => HashAlgo::sha1(),
        HashAlgorithm::Sha256 => HashAlgo::sha256(),
        HashAlgorithm::Sha384 => HashAlgo::sha384(),
        HashAlgorithm::Sha512 => HashAlgo::sha512(),
    };

    // Query the required buffer size
    let size = hash_algo.hash(data, None).map_err(|e| {
        tracing::error!(?e, "Hash size query failed");
        ManticoreError::ShaError
    })?;

    // Allocate buffer and compute hash
    let mut output = vec![0u8; size];
    hash_algo.hash(data, Some(&mut output)).map_err(|e| {
        tracing::error!(?e, "Hash operation failed");
        ManticoreError::ShaError
    })?;

    Ok(output)
}

/// HMAC-SHA-384 operation.
pub fn hmac_sha_384(key: &[u8], data: &[u8]) -> Result<[u8; 48], ManticoreError> {
    if key.len() != 48 {
        tracing::error!(
            error=?ManticoreError::HmacError,
            key_len = key.len(),
            expected = 48,
            "Expected HMAC key size is 48 bytes for HMAC-SHA-384"
        );
        return Err(ManticoreError::HmacError);
    }

    // Create HMAC key from bytes
    let hmac_key = HmacKey::from_bytes(key).map_err(|e| {
        tracing::error!(?e, "Failed to create HMAC key");
        ManticoreError::HmacError
    })?;

    // Create HMAC algorithm with SHA-384
    let mut hmac_algo = HmacAlgo::new(HashAlgo::sha384());

    // Query the required signature size
    let size = hmac_algo.sign(&hmac_key, data, None).map_err(|e| {
        tracing::error!(?e, "HMAC size query failed");
        ManticoreError::HmacError
    })?;

    if size != 48 {
        tracing::error!(
            error=?ManticoreError::HmacError,
            size,
            expected = 48,
            "Expected HMAC size is 48 for HMAC-SHA-384"
        );
        return Err(ManticoreError::HmacError);
    }

    // Compute HMAC
    let mut output = [0u8; 48];
    hmac_algo
        .sign(&hmac_key, data, Some(&mut output))
        .map_err(|e| {
            tracing::error!(?e, "HMAC operation failed");
            ManticoreError::HmacError
        })?;

    Ok(output)
}

/// HKDF-SHA-256 operation.
///
/// # Arguments
/// * `data` - Shared secret data to derive from
/// * `info` - Optional context and application-specific information
/// * `out_len` - Size of data to derive
///
/// # Returns
/// * `Vec<u8>` - The derivation result, with `out_len` length.
///
/// # Errors
/// * `ManticoreError::HkdfError` - If the HKDF operation fails.
pub fn hkdf_sha_256_derive(
    data: &[u8],
    info: Option<&[u8]>,
    out_len: usize,
) -> Result<Vec<u8>, ManticoreError> {
    // Create secret key from input data
    let secret_key = GenericSecretKey::from_bytes(data).map_err(|e| {
        tracing::error!(?e, "Failed to create secret key from data");
        ManticoreError::HkdfError
    })?;

    // Create hash algorithm (needs to live long enough for HKDF)
    let hash_algo = HashAlgo::sha256();

    // Create HKDF algorithm with SHA-256, ExtractAndExpand mode
    let hkdf_algo = HkdfAlgo::new(
        HkdfMode::ExtractAndExpand,
        &hash_algo,
        None, // No salt
        info,
    );

    // Derive key material
    let derived_key = hkdf_algo.derive(&secret_key, out_len).map_err(|e| {
        tracing::error!(?e, "HKDF derivation failed");
        ManticoreError::HkdfError
    })?;

    // Convert to Vec<u8>
    derived_key.to_vec().map_err(|e| {
        tracing::error!(?e, "Failed to convert derived key to bytes");
        ManticoreError::HkdfError
    })
}

#[cfg(test)]
mod tests {
    use test_with_tracing::test;

    use super::*;

    #[test]
    fn test_sha() {
        const DATA: [u8; 1024] = [1u8; 1024];

        const EXPECTED_SHA1: [u8; 20] = [
            0x37, 0x6f, 0x19, 0x00, 0x1d, 0xc1, 0x71, 0xe2, 0xeb, 0x9c, 0x56, 0x96, 0x2c, 0xa3,
            0x24, 0x78, 0xca, 0xaa, 0x7e, 0x39,
        ];

        const EXPECTED_SHA256: [u8; 32] = [
            0x5a, 0x64, 0x8d, 0x80, 0x15, 0x90, 0x0d, 0x89, 0x66, 0x4e, 0x00, 0xe1, 0x25, 0xdf,
            0x17, 0x96, 0x36, 0x30, 0x1a, 0x2d, 0x8f, 0xa1, 0x91, 0xc1, 0xaa, 0x2b, 0xd9, 0x35,
            0x8e, 0xa5, 0x3a, 0x69,
        ];

        const EXPECTED_SHA384: [u8; 48] = [
            0x45, 0x73, 0x0a, 0x19, 0xac, 0xff, 0x84, 0x81, 0xe7, 0xe2, 0xb9, 0x9c, 0x41, 0x00,
            0xa0, 0x9a, 0x02, 0x88, 0xa3, 0xbc, 0x45, 0xdf, 0x56, 0xff, 0x7e, 0x72, 0xdd, 0x92,
            0xef, 0x9e, 0x4c, 0x92, 0xf9, 0x25, 0xc9, 0xd6, 0xba, 0x1e, 0xa9, 0x6c, 0x93, 0x4a,
            0x5f, 0x1e, 0x78, 0x2a, 0x7c, 0xc7,
        ];

        const EXPECTED_SHA512: [u8; 64] = [
            0x19, 0xc6, 0x84, 0x1f, 0x3d, 0x6e, 0x33, 0xa4, 0xd2, 0x8e, 0x7c, 0xb4, 0x7f, 0xf9,
            0x38, 0x72, 0x84, 0x79, 0xc5, 0x6b, 0xb9, 0x30, 0xf3, 0xe8, 0x53, 0x5e, 0xc2, 0x4d,
            0x94, 0x53, 0xd9, 0x66, 0x5b, 0x7d, 0xc1, 0x16, 0x31, 0x81, 0xb9, 0x4a, 0x1a, 0xda,
            0x95, 0x54, 0xe9, 0x53, 0xa0, 0x94, 0xed, 0x44, 0xfd, 0x6f, 0xae, 0xe7, 0xa9, 0xbb,
            0xde, 0x66, 0x15, 0x37, 0x5b, 0xab, 0x4a, 0xe8,
        ];

        let result = sha(HashAlgorithm::Sha1, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA1);

        let result = sha(HashAlgorithm::Sha256, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA256);

        let result = sha(HashAlgorithm::Sha384, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA384);

        let result = sha(HashAlgorithm::Sha512, &DATA);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EXPECTED_SHA512);
    }
}
