// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! HMAC key utilities for the AziHSM project.
//!
//! This module provides common functions and structures related to HMAC key size validation and key range definitions.
//! It is intended to be used by all platform-specific HMAC implementations to ensure consistent key size enforcement.

use super::*;

/// Represents the valid key size range (in bytes) for a given HMAC algorithm.
pub struct HmacKeyRange {
    /// The minimum allowed key size (inclusive).
    pub lower_bound: usize,
    /// The maximum allowed key size (inclusive).
    pub upper_bound: usize,
}

impl HmacKey {
    /// Returns the lower and upper key size bounds for the specified hash algorithm.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm for which to get the key size range.
    ///
    /// # Returns
    /// * `HmacKeyRange` with the lower and upper bounds (in bytes) for the key size.
    ///
    /// # Example
    /// ```
    /// let range = HmacKey::get_lower_upper_key_size(HashAlgo::Sha256);
    /// assert_eq!(range.lower_bound, 32);
    /// assert_eq!(range.upper_bound, 64);
    /// ```
    pub fn get_lower_upper_key_size(hash_algo: HashAlgo) -> HmacKeyRange {
        // HmacSha1: 20-40 bytes
        // HmacSha256: 32-64 bytes
        // HmacSha384: 48-96 bytes
        // HmacSha512: 64-128 bytes
        match hash_algo {
            HashAlgo::Sha1 => HmacKeyRange {
                lower_bound: 20,
                upper_bound: 40,
            },
            HashAlgo::Sha256 => HmacKeyRange {
                lower_bound: 32,
                upper_bound: 64,
            },
            HashAlgo::Sha384 => HmacKeyRange {
                lower_bound: 48,
                upper_bound: 96,
            },
            HashAlgo::Sha512 => HmacKeyRange {
                lower_bound: 64,
                upper_bound: 128,
            },
        }
    }
}

impl HmacKeyOp for HmacKey {
    /// Creates an `HmacKey` from a slice of bytes.
    ///
    /// # Arguments
    /// * `key` - The key material as a byte slice. Must be non-empty and within the allowed key size range for HMAC algorithms.
    ///
    /// # Returns
    /// * `Ok(HmacKey)` if the key is valid and created successfully.
    /// * `Err(CryptoError)` if the key is empty, too short, or too long.
    fn from_slice(key: &[u8]) -> Result<HmacKey, CryptoError> {
        // Check if the passed slice is empty
        if key.is_empty() {
            tracing::error!("HmacKey::from_slice called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Accept HmacOnly if it is in valid range
        let min_len = Self::get_lower_upper_key_size(HashAlgo::Sha1).lower_bound;
        let max_len = Self::get_lower_upper_key_size(HashAlgo::Sha512).upper_bound;
        if key.len() < min_len {
            tracing::error!(
                "HmacKey::from_slice key too short: {} < {}",
                key.len(),
                min_len
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if key.len() > max_len {
            tracing::error!(
                "HmacKey::from_slice key too long: {} > {}",
                key.len(),
                max_len
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        Ok(HmacKey { key: key.to_vec() })
    }
}
