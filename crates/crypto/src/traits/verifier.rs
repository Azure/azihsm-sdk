// Copyright (C) Microsoft Corporation. All rights reserved.

//! Verification operation wrapper.
//!
//! This module provides a unified interface for verification operations, supporting
//! both single-operation and streaming verification modes.

use super::*;

/// Verification operation wrapper.
///
/// This structure provides a unified interface for signature verification operations,
/// wrapping the underlying algorithm-specific implementations to provide a consistent API.
pub struct Verifier;

impl Verifier {
    /// Performs single-operation signature verification.
    ///
    /// This method verifies a digital signature in a single call using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The verification algorithm implementation
    /// * `key` - The public key to use for verification
    /// * `data` - Input data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The signature is malformed
    /// - The underlying cryptographic operation fails
    pub fn verify<Algo: VerifyOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        algo.verify(key, data, signature)
    }

    /// Performs signature verification with message recovery.
    ///
    /// This method verifies a digital signature and recovers the signed message
    /// in a single operation. Used for signature schemes that embed the message
    /// within the signature (e.g., RSA with message recovery).
    ///
    /// # Arguments
    ///
    /// * `algo` - The verification algorithm implementation
    /// * `key` - The public key to use for verification
    /// * `signature` - The signature to verify and recover from
    /// * `output` - Optional output buffer for the recovered message. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The signature is malformed or invalid
    /// - The output buffer is too small
    /// - The underlying cryptographic operation fails
    pub fn verify_recover<Algo: VerifyRecoverOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        signature: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.verify_recover(key, signature, output)
    }

    /// Performs signature verification with message recovery, returning a vector.
    ///
    /// This is a convenience method that allocates the necessary output buffer,
    /// verifies the signature, recovers the message, and returns it as a `Vec<u8>`.
    ///
    /// # Arguments
    ///
    /// * `algo` - The verification algorithm implementation
    /// * `key` - The public key to use for verification
    /// * `signature` - The signature to verify and recover from
    ///
    /// # Returns
    ///
    /// Returns a vector containing the recovered message.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The signature is malformed or invalid
    /// - The underlying cryptographic operation fails
    pub fn verify_recover_vec<Algo: VerifyRecoverOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        signature: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let required_size = algo.verify_recover(key, signature, None)?;
        let mut output = vec![0u8; required_size];
        let written_size = algo.verify_recover(key, signature, Some(&mut output))?;
        output.truncate(written_size);
        Ok(output)
    }

    /// Initializes a streaming verification context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations.
    ///
    /// # Arguments
    ///
    /// * `algo` - The streaming verification algorithm implementation
    /// * `key` - The public key to use for verification
    ///
    /// # Returns
    ///
    /// Returns a [`VerifierContext`] that can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The underlying cryptographic provider fails to initialize
    pub fn verify_init<'a, Algo: VerifyStreamingOp<'a>>(
        algo: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, CryptoError> {
        algo.verify_init(key)
    }
}
