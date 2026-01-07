// Copyright (C) Microsoft Corporation. All rights reserved.

//! Signature operation wrapper.
//!
//! This module provides a unified interface for signature operations, supporting
//! both single-operation and streaming signature modes.

use super::*;

/// Signature operation wrapper.
///
/// This structure provides a unified interface for signature operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct Signer;

impl Signer {
    /// Performs single-operation signing.
    ///
    /// This method creates a digital signature in a single call using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The signing algorithm implementation
    /// * `key` - The private key to use for signing
    /// * `data` - Input data to sign
    /// * `signature` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    pub fn sign<Algo: SignOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.sign(key, data, signature)
    }

    /// Performs single-operation signing and returns the result as a vector.
    ///
    /// This is a convenience method that allocates a buffer and returns the signature
    /// as a `Vec<u8>`, avoiding the need for manual buffer management.
    ///
    /// # Arguments
    ///
    /// * `algo` - The signing algorithm implementation
    /// * `key` - The private key to use for signing
    /// * `data` - Input data to sign
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the computed signature.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - Memory allocation fails
    /// - The underlying cryptographic operation fails
    pub fn sign_vec<Algo: SignOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let sig_len = Self::sign(algo, key, data, None)?;
        let mut signature = vec![0u8; sig_len];
        Self::sign(algo, key, data, Some(&mut signature))?;
        Ok(signature)
    }

    /// Initializes a streaming signature context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations.
    ///
    /// # Arguments
    ///
    /// * `algo` - The streaming signing algorithm implementation
    /// * `key` - The private key to use for signing
    ///
    /// # Returns
    ///
    /// Returns a [`SignerContext`] that can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The underlying cryptographic provider fails to initialize
    pub fn sign_init<'a, Algo: SignStreamingOp<'a>>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, CryptoError> {
        algo.sign_init(key)
    }
}
