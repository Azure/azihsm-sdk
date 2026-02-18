// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hash operation wrapper.
//!
//! This module provides a unified interface for hashing operations, supporting
//! both single-operation and streaming hash modes.

use super::*;

/// Hash operation wrapper.
///
/// This structure provides a unified interface for hashing operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
pub struct Hasher;

impl Hasher {
    /// Performs single-operation hashing.
    ///
    /// This method computes a hash in a single call using the provided
    /// algorithm implementation.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hashing algorithm implementation
    /// * `data` - Input data to hash
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer (hash length), or the
    /// required buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying cryptographic operation fails
    pub fn hash<Algo: HashOp>(
        algo: &mut Algo,
        data: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        algo.hash(data, output)
    }

    /// Performs single-operation hashing and returns the result as a vector.
    ///
    /// This is a convenience method that allocates a buffer and returns the hash
    /// digest as a `Vec<u8>`, avoiding the need for manual buffer management.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hashing algorithm implementation
    /// * `data` - Input data to hash
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the computed hash digest.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails
    /// - The underlying cryptographic operation fails
    pub fn hash_vec<Algo: HashOp>(algo: &mut Algo, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // First, query the required buffer size
        let hash_size = algo.hash(data, None)?;
        let mut digest = vec![0u8; hash_size];
        let written = Hasher::hash(algo, data, Some(digest.as_mut_slice()))?;
        digest.truncate(written);
        Ok(digest)
    }

    /// Initializes a streaming hash context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations.
    ///
    /// # Arguments
    ///
    /// * `algo` - The streaming hashing algorithm implementation
    ///
    /// # Returns
    ///
    /// Returns a [`HasherContext`] that can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying cryptographic provider fails to initialize
    /// - Memory allocation fails
    pub fn hash_init<Algo: HashStreamingOp>(algo: Algo) -> Result<Algo::Context, CryptoError> {
        algo.hash_init()
    }
}
