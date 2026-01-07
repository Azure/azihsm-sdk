// Copyright (C) Microsoft Corporation. All rights reserved.

//! Decryption operation wrapper.
//!
//! This module provides a unified interface for decryption operations, supporting
//! both single-operation and streaming decryption modes.

use super::*;

/// Decryption operation wrapper.
///
/// This structure provides a unified interface for decryption operations, supporting
/// both single-operation and streaming decryption modes. It wraps the underlying
/// algorithm-specific implementations and provides a consistent API.
pub struct Decrypter;

impl Decrypter {
    /// Performs single-operation decryption.
    ///
    /// This method decrypts complete messages in a single call using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The decryption algorithm implementation
    /// * `key` - The secret key to use for decryption
    /// * `input` - Input ciphertext data to decrypt
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
    /// - The input data is invalid (e.g., wrong padding, authentication failure)
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    pub fn decrypt<Algo: DecryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.decrypt(key, input, output)
    }

    /// Performs single-operation decryption and returns the result as a new vector.
    ///
    /// This is a convenience method that allocates the output buffer automatically.
    /// It first queries the required size, allocates a vector, then performs the
    /// decryption operation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The decryption algorithm implementation
    /// * `key` - The secret key to use for decryption
    /// * `input` - Input ciphertext data to decrypt
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ciphertext is invalid or corrupted
    /// - Authentication verification fails
    /// - The key is invalid for this operation
    /// - The underlying cryptographic operation fails
    pub fn decrypt_vec<Algo: DecryptOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        input: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let required_size = algo.decrypt(key, input, None)?;
        let mut output = vec![0u8; required_size];
        let written_size = algo.decrypt(key, input, Some(&mut output))?;
        output.truncate(written_size);
        Ok(output)
    }

    /// Initializes a streaming decryption context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations.
    ///
    /// # Arguments
    ///
    /// * `algo` - The streaming decryption algorithm implementation
    /// * `key` - The secret key to use for decryption
    ///
    /// # Returns
    ///
    /// Returns a [`DecrypterContext`] that can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - Initialization vector (IV) or other parameters are invalid
    /// - The underlying cryptographic provider fails to initialize
    pub fn decrypt_init<'a, Algo: DecryptStreamingOp<'a>>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, CryptoError> {
        let context = algo.decrypt_init(key)?;
        Ok(context)
    }
}
