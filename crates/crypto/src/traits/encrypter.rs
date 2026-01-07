// Copyright (C) Microsoft Corporation. All rights reserved.

//! Encryption operation wrapper.
//!
//! This module provides a unified interface for encryption operations, supporting
//! both single-operation and streaming encryption modes.

use super::*;

/// Encryption operation wrapper.
///
/// This structure provides a unified interface for encryption operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct Encrypter;

impl Encrypter {
    /// Performs single-operation encryption.
    ///
    /// This method encrypts complete messages in a single call using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The encryption algorithm implementation
    /// * `key` - The secret key to use for encryption
    /// * `input` - Input plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    pub fn encrypt<Algo: EncryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.encrypt(key, input, output)
    }

    /// Performs single-operation encryption and returns the result as a new vector.
    ///
    /// This is a convenience method that allocates the output buffer automatically.
    /// It first queries the required size, allocates a vector, then performs the
    /// encryption operation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The encryption algorithm implementation
    /// * `key` - The secret key to use for encryption
    /// * `input` - Input plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the encrypted ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    pub fn encrypt_vec<Algo: EncryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let required_size = algo.encrypt(key, input, None)?;
        let mut output = vec![0u8; required_size];
        let written_size = algo.encrypt(key, input, Some(&mut output))?;
        output.truncate(written_size);
        Ok(output)
    }

    /// Initializes a streaming encryption context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations.
    ///
    /// # Arguments
    ///
    /// * `algo` - The streaming encryption algorithm implementation
    /// * `key` - The secret key to use for encryption
    ///
    /// # Returns
    ///
    /// Returns an [`EncrypterContext`] that can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - Initialization vector (IV) or other parameters are invalid
    /// - The underlying cryptographic provider fails to initialize
    pub fn encrypt_init<'a, Algo: EncryptStreamingOp<'a>>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, CryptoError> {
        algo.encrypt_init(key)
    }
}
