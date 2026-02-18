// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//! Decoding operation wrapper.
//!
//! This module provides a unified interface for decoding operations, supporting
//! various decoding schemes used throughout the crypto library.

use super::*;

/// Decoding operation wrapper.
///
/// This structure provides a unified interface for decoding operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct Decoder;

impl Decoder {
    /// Decodes data using the specified algorithm.
    ///
    /// This method decodes a byte representation back into a structured data type
    /// using the provided algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `input` - The byte representation to decode
    /// * `params` - Parameters required for decoding (use `()` if none needed)
    ///
    /// # Returns
    ///
    /// Returns the decoded data structure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input format is invalid
    /// - Insufficient input data is provided
    /// - The underlying decoding operation fails
    /// - Validation of the decoded data fails
    pub fn decode<Algo: DecodeOp>(input: &[u8], params: Algo::P) -> Result<Algo::T, CryptoError> {
        Algo::from_bytes(input, params)
    }
}
