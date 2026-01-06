// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key derivation operation wrapper.
//!
//! This module provides a unified interface for key derivation operations.

use super::*;

/// Key derivation operation wrapper.
///
/// This structure provides a unified interface for key derivation operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct KeyDeriver;

impl KeyDeriver {
    /// Performs key derivation.
    ///
    /// This method derives a new cryptographic key from source key material
    /// using the provided algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The key derivation algorithm implementation
    /// * `key` - The source key material to derive from
    /// * `derived_len` - The desired length of the derived key in bytes
    ///
    /// # Returns
    ///
    /// Returns the successfully derived key of the specified length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source key is invalid or has incorrect properties
    /// - The requested derived key length is invalid or unsupported
    /// - The derivation algorithm fails
    /// - The underlying cryptographic operation fails
    pub fn derive<Algo: DeriveOp>(
        algo: &Algo,
        key: &Algo::Key,
        derived_len: usize,
    ) -> Result<Algo::DerivedKey, CryptoError> {
        algo.derive(key, derived_len)
    }
}
