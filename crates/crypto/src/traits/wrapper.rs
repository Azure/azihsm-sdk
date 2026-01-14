// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key wrapping operation wrapper.
//!
//! This module provides a unified interface for key wrapping operations.

use super::*;

/// Key wrapping operation wrapper.
///
/// This structure provides a unified interface for key wrapping operations,
/// wrapping the underlying algorithm-specific implementations to provide a consistent API.
pub struct KeyWrapper;

impl KeyWrapper {
    /// Wraps (encrypts) a target key using a wrapping key.
    ///
    /// This method encrypts the target key with the wrapping key, producing
    /// wrapped key material that includes both the encrypted key and integrity
    /// information.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key wrapping algorithm implementation
    /// * `key` - The wrapping key (KEK) used to encrypt the target key
    /// * `target_key` - The key to be wrapped (encrypted)
    /// * `wrapped_key` - Optional output buffer for the wrapped key material.
    ///   If `None`, only returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer, or the required
    /// buffer size if `wrapped_key` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The wrapping key is invalid or lacks appropriate permissions
    /// - The target key cannot be exported/wrapped
    /// - The underlying cryptographic operation fails
    pub fn wrap<Algo: WrapOp, TargetKey: ExportableKey>(
        algo: &mut Algo,
        key: &Algo::Key,
        target_key: &TargetKey,
        wrapped_key: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.wrap_key(key, target_key, wrapped_key)
    }

    /// Wraps a target key and returns the result as a vector.
    ///
    /// This is a convenience method that allocates a buffer and returns the
    /// wrapped key material as a `Vec<u8>`, avoiding the need for manual buffer management.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key wrapping algorithm implementation
    /// * `key` - The wrapping key (KEK) used to encrypt the target key
    /// * `target_key` - The key to be wrapped (encrypted)
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the wrapped key material.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The wrapping key is invalid or lacks appropriate permissions
    /// - The target key cannot be exported/wrapped
    /// - Memory allocation fails
    /// - The underlying cryptographic operation fails
    pub fn wrap_vec<Algo: WrapOp, TargetKey: ExportableKey>(
        algo: &mut Algo,
        key: &Algo::Key,
        target_key: &TargetKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let wrapped_len = Self::wrap(algo, key, target_key, None)?;
        let mut wrapped_key = vec![0u8; wrapped_len];
        Self::wrap(algo, key, target_key, Some(&mut wrapped_key))?;
        Ok(wrapped_key)
    }
}
