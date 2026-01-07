// Copyright (C) Microsoft Corporation. All rights reserved.

//! Encoding and decoding traits for cryptographic operations.
//!
//! This module defines generic traits for encoding data structures to byte
//! representations and decoding them back. These traits are used throughout
//! the crypto library for various operations including:
//!
//! - RSA padding schemes (PKCS#1, OAEP, PSS)
//! - DER encoding/decoding for keys and certificates
//! - Protocol message encoding/decoding
//!
//! # Design Pattern
//!
//! The encoding/decoding pattern follows a two-phase approach:
//!
//! 1. **Size Query**: Call with `None` output to determine required buffer size
//! 2. **Encoding**: Call with `Some(buffer)` to perform actual encoding
//!
//! This pattern avoids unnecessary allocations when the caller provides a buffer,
//! while still supporting dynamic allocation via the `to_vec()` helper method.

use super::*;

/// Trait for encoding data structures to byte representations.
///
/// This trait provides a generic interface for converting data structures
/// into their byte representation. Implementors can support both querying
/// the required output size and performing the actual encoding.
///
/// # Implementation Pattern
///
/// Implementors should:
/// 1. Calculate the output size
/// 2. If `output` is `None`, return the size without encoding
/// 3. If `output` is `Some`, validate buffer size and perform encoding
/// 4. Return the actual number of bytes written
pub trait EncodeOp {
    /// Encodes the data structure to bytes.
    ///
    /// This method supports two modes of operation:
    ///
    /// - **Size Query**: When `output` is `None`, returns the required buffer size
    ///   without performing encoding
    /// - **Encoding**: When `output` is `Some`, encodes into the provided buffer
    ///
    /// # Arguments
    ///
    /// * `output` - Optional mutable buffer for the encoded output
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes required (if `output` is `None`) or
    ///   written (if `output` is `Some`)
    /// * `Err(CryptoError)` - If encoding fails or buffer is too small
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Buffer too small for the encoded output
    /// - Invalid data structure state
    /// - Encoding operation failure
    fn to_bytes(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError>;
}

/// Trait for decoding byte representations back to data structures.
///
/// This trait provides a generic interface for parsing byte representations
/// and constructing data structures from them. It supports parameterized
/// decoding where additional configuration is required.
///
/// # Type Parameters
///
/// - `T`: The type of the decoded output
/// - `P`: The type of parameters required for decoding (use `()` if none needed)
///
/// # Implementation Pattern
///
/// Implementors should:
/// 1. Validate input format and parameters
/// 2. Parse the byte representation
/// 3. Construct and return the decoded structure
/// 4. Return appropriate errors for invalid input
pub trait DecodeOp {
    /// The type of the decoded output.
    type T;

    /// The type of parameters required for decoding.
    ///
    /// Use `()` if no parameters are needed. For complex decoding operations
    /// that require configuration (e.g., key size, algorithm selection),
    /// define a custom parameter struct.
    type P;

    /// Decodes a byte representation into a data structure.
    ///
    /// This method parses the input bytes according to the expected format
    /// and constructs the corresponding data structure. Additional parameters
    /// can be provided for configuration.
    ///
    /// # Arguments
    ///
    /// * `input` - The byte representation to decode
    /// * `params` - Parameters required for decoding (use `()` if none needed)
    ///
    /// # Returns
    ///
    /// * `Ok(T)` - The decoded data structure
    /// * `Err(CryptoError)` - If decoding fails
    ///
    /// # Errors
    ///
    /// Common error cases include:
    /// - Invalid input format
    /// - Insufficient input data
    /// - Unsupported version or algorithm
    /// - Validation failure
    fn from_bytes(input: &[u8], params: Self::P) -> Result<Self::T, CryptoError>;
}
