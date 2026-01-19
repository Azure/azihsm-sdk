// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key unwrapping operation wrapper.
//!
//! This module provides a unified interface for key unwrapping operations.

use super::*;

/// Key unwrapping operation wrapper.
///
/// This structure provides a unified interface for key unwrapping operations,
/// wrapping the underlying algorithm-specific implementations to provide a consistent API.
pub struct KeyUnwrapper;

impl KeyUnwrapper {
    /// Unwraps (decrypts) a wrapped key using an unwrapping key.
    ///
    /// This method decrypts wrapped key material using the unwrapping key,
    /// verifies its integrity, and recovers the original plaintext key.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key unwrapping algorithm implementation
    /// * `key` - The unwrapping key (KEK) used to decrypt the wrapped key
    /// * `wrapped_key` - The wrapped (encrypted) key material to unwrap
    ///
    /// # Returns
    ///
    /// Returns the unwrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The unwrapping key is invalid or lacks appropriate permissions
    /// - The wrapped key material is corrupted or has been tampered with
    /// - Integrity verification fails
    /// - The underlying cryptographic operation fails
    pub fn unwrap<Algo: UnwrapOp, TargetKey: ImportableKey>(
        algo: &mut Algo,
        key: &Algo::Key,
        wrapped_key: &[u8],
    ) -> Result<TargetKey, CryptoError> {
        algo.unwrap_key(key, wrapped_key)
    }
}
