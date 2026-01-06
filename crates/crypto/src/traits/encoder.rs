// Copyright (C) Microsoft Corporation. All rights reserved.
//! Encoding operation wrapper.
//!
//! This module provides a unified interface for encoding operations, supporting
//! various encoding schemes used throughout the crypto library.

use super::*;

/// Encoding operation wrapper.
///
/// This structure provides a unified interface for encoding operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct Encoder;

impl Encoder {
    /// Encodes data using the specified algorithm.
    ///
    /// This method encodes data into a byte representation using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The encoding algorithm implementation
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
    /// - The data is invalid for encoding
    /// - The underlying encoding operation fails
    pub fn encode<Algo: EncodeOp>(
        algo: &mut Algo,
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.to_bytes(output)
    }

    /// Encodes data and returns the result as a vector.
    ///
    /// This is a convenience method that allocates a buffer and returns the encoded
    /// data as a `Vec<u8>`, avoiding the need for manual buffer management.
    ///
    /// # Arguments
    ///
    /// * `algo` - The encoding algorithm implementation
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the encoded data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data is invalid for encoding
    /// - Memory allocation fails
    /// - The underlying encoding operation fails
    pub fn encode_vec<Algo: EncodeOp>(algo: &mut Algo) -> Result<Vec<u8>, CryptoError> {
        let size = Self::encode(algo, None)?;
        let mut buffer = vec![0u8; size];
        let len = Self::encode(algo, Some(&mut buffer))?;
        buffer.truncate(len);
        Ok(buffer)
    }
}
