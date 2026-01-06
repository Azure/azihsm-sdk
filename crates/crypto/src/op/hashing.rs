// Copyright (C) Microsoft Corporation. All rights reserved.
//! Traits for cryptographic hash operations.
//!
//! This module provides trait definitions for both single-operation and streaming
//! hash computation. These traits abstract over different hash algorithms (e.g.,
//! SHA-1, SHA-256, SHA-384, SHA-512) while providing a consistent interface.
//!
//! # Design
//!
//! The module provides two levels of hashing APIs:
//!
//! - **Single-operation**: [`HashingOp`] for computing hashes over complete messages
//!   in a single call. Suitable for small messages or when all data is available at once.
//!
//! - **Streaming**: [`StreamingHashingOp`] and [`StreamingHashingOpContext`] for
//!   processing data in chunks. Useful for large messages, streaming data, or when
//!   memory constraints prevent loading entire messages.
//!
//! # Hash Algorithms
//!
//! These traits support various cryptographic hash functions including:
//! - SHA-1 (deprecated for cryptographic use, provided for compatibility)
//! - SHA-256, SHA-384, SHA-512 (SHA-2 family)
//! - Future algorithms as needed

use super::*;

/// Trait for single-operation cryptographic hashing.
///
/// This trait provides a unified interface for computing cryptographic hashes over
/// complete messages in a single operation. It's suitable for algorithms where all
/// data is available in memory.
///
/// # Design Pattern
///
/// The trait uses an optional output buffer pattern:
/// - When `output` is `None`: Returns the required output buffer size (hash length)
/// - When `output` is `Some`: Performs the actual hash computation
///
/// This allows callers to determine buffer requirements before performing
/// the actual computation.
///
/// # Implementation Requirements
///
/// Implementors must:
/// - Produce cryptographically correct hash values
/// - Return accurate output size when `output` is `None`
/// - Validate buffer sizes and return appropriate errors
/// - Use platform-optimized implementations when available
pub trait HashOp {
    /// Computes a cryptographic hash of the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - The input data to hash
    /// * `output` - Optional output buffer for the hash digest. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size (hash length) if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small for the hash result
    /// - The underlying cryptographic operation fails
    fn hash(&mut self, data: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError>;
}

/// Trait for streaming cryptographic hash operations.
///
/// This trait provides an interface for multi-step hash computation where
/// data is processed in chunks. This is useful for:
/// - Large files that don't fit in memory
/// - Streaming data sources (network, pipes)
/// - Progressive hashing with intermediate state
///
/// # Lifecycle
///
/// 1. Initialize: Call [`hash_init`](Self::hash_init) to create a context
/// 2. Update: Call [`update`](StreamingHashingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](StreamingHashingOpContext::finish) to produce the hash digest
///
/// # State Management
///
/// The context maintains internal hash state including:
/// - Algorithm-specific state (e.g., working variables)
/// - Buffered partial blocks
/// - Total input length counters
pub trait HashStreamingOp {
    /// The context type for streaming hash operations.
    type Context: HashOpContext<Algo = Self>;

    /// Initializes a streaming hash computation context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state across multiple
    /// [`update`](HashOpContext::update) calls until
    /// [`finish`](HashOpContext::finish) is called.
    ///
    /// # Returns
    ///
    /// Returns a boxed context implementing [`HashOpContext`] that
    /// can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying cryptographic provider fails to initialize
    /// - Memory allocation fails
    fn hash_init(self) -> Result<Self::Context, CryptoError>;
}

/// Context for streaming cryptographic hash operations.
///
/// This trait represents an active hash computation that processes data
/// incrementally. Contexts are created by [`StreamingHashingOp::hash_init`]
/// and maintain internal state across multiple updates.
///
/// # Lifecycle
///
/// 1. Create context via [`StreamingHashingOp::hash_init`]
/// 2. Process data chunks with [`update`](Self::update) (can be called multiple times)
/// 3. Complete operation with [`finish`](Self::finish) to produce the hash digest
///
/// # State Management
///
/// The context maintains:
/// - Internal algorithm state (e.g., hash state variables)
/// - Buffered partial blocks (hash algorithms process fixed-size blocks)
/// - Total input length for padding computation
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe. Each context should be used from
/// a single thread. For concurrent hashing, create separate contexts.
pub trait HashOpContext {
    /// The associated hash algorithm type.
    type Algo: HashStreamingOp<Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state. The data is processed according
    /// to the hash algorithm's block size, with partial blocks buffered internally.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation has already been finalized
    /// - The underlying hash operation fails
    /// - Memory allocation fails
    ///
    /// # Performance
    ///
    /// - Optimized for processing data in chunks
    /// - Automatically handles block-level buffering
    /// - Utilizes platform-specific optimizations and hardware acceleration
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalizes the hash computation and produces the digest.
    ///
    /// This method completes the hash computation by:
    /// 1. Processing any remaining buffered data
    /// 2. Applying padding according to the algorithm specification
    /// 3. Producing the final hash digest
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer for the hash digest. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size (hash length) if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small for the hash result
    /// - The underlying finalization operation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// A new context must be created for additional hash computations.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the hash computation and returns the digest as a `Vec<u8>`.
    ///
    /// This is a convenience method that automatically allocates a buffer of the
    /// correct size for the hash digest and returns it as a vector. It internally
    /// calls [`finish`](Self::finish) twice: once to determine the required size,
    /// and once to compute the hash into the allocated buffer.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the complete hash digest. The vector's length
    /// matches the hash algorithm's output size (e.g., 32 bytes for SHA-256).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying finalization operation fails
    /// - Memory allocation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    fn finish_vec(&mut self) -> Result<Vec<u8>, CryptoError> {
        let hash_size = self.finish(None)?;
        let mut hash_buf = vec![0u8; hash_size];
        self.finish(Some(&mut hash_buf))?;
        Ok(hash_buf)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// This method provides access to the algorithm instance associated with
    /// this hash context.
    ///
    /// # Returns
    ///
    /// A reference to the hash algorithm.
    fn algo(&self) -> &Self::Algo;

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// This method provides mutable access to the algorithm instance associated
    /// with this hash context.
    ///
    /// # Returns
    ///
    /// A mutable reference to the hash algorithm.
    fn algo_mut(&mut self) -> &mut Self::Algo;

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// This method takes ownership of the context and returns the hash algorithm
    /// instance, allowing the algorithm to be reused or inspected after the
    /// context is no longer needed.
    ///
    /// # Returns
    ///
    /// The hash algorithm instance.
    fn into_algo(self) -> Self::Algo;
}
