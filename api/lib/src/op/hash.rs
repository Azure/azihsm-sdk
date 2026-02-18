// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hash operation wrapper.
//!
//! This module provides a unified interface for hashing operations, supporting
//! both single-operation and streaming hash modes. It acts as a convenience
//! wrapper around the hash algorithm implementations, providing a consistent
//! API pattern across different hash algorithms.
//!
//! # Design Pattern
//!
//! The wrapper follows the "newtype" pattern to:
//! - Provide algorithm-agnostic interfaces
//! - Simplify common hashing operations
//! - Abstract over single-shot vs streaming modes
//! - Enable consistent error handling
//!
//! # Operation Modes
//!
//! ## Single-shot Operations
//!
//! Complete hash computation in a single function call. Suitable for:
//! - Small to medium-sized data that fits in memory
//! - Data available as a contiguous byte slice
//! - Scenarios where simplicity is preferred over memory efficiency
//!
//! ## Streaming Operations
//!
//! Incremental hash computation through multiple update calls. Suitable for:
//! - Large files or datasets that don't fit in memory
//! - Data arriving from network streams or pipes
//! - Real-time processing with limited memory
//! - Progressive computation as data becomes available
//!
//! # Thread Safety
//!
//! The wrapper itself is stateless and can be used concurrently. However,
//! individual hash contexts and sessions are not thread-safe and should
//! be used from a single thread.

use super::*;

/// Hash operation wrapper.
///
/// This structure provides a unified interface for hashing operations, wrapping
/// the underlying algorithm-specific implementations to provide a consistent API.
/// It is implemented as a zero-sized type (ZST) with only static methods,
/// incurring no runtime overhead.
///
/// # Purpose
///
/// `HsmHasher` serves as a facade that:
/// - Abstracts over different hash algorithm implementations
/// - Provides convenient methods for common operations
/// - Maintains consistent API patterns across algorithms
/// - Simplifies buffer management for hash output
///
/// # Design
///
/// The wrapper is stateless and algorithm-agnostic. Actual hash computation
/// is delegated to specific algorithm implementations (SHA-256, SHA-512, etc.)
/// that implement the `HsmHashOp` and `HsmHashStreamingOp` traits.
///
/// # Zero-Cost Abstraction
///
/// Being a zero-sized type with static methods, `HsmHasher` provides no runtime
/// overhead compared to calling the algorithm implementations directly. The
/// wrapper methods are typically inlined by the compiler.
pub struct HsmHasher;

impl HsmHasher {
    /// Performs single-operation hashing.
    ///
    /// This method computes a hash in a single call using the provided
    /// algorithm implementation. It processes all input data at once and
    /// produces the complete hash digest.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session in which to perform the operation.
    ///   Provides context for session-specific resources and state.
    /// * `algo` - The hashing algorithm implementation (SHA-1, SHA-256, etc.).
    ///   Must implement the `HsmHashOp` trait.
    /// * `data` - Input data to hash. Can be any length from 0 bytes to
    ///   gigabytes. Empty slices are valid and produce the hash of empty input.
    /// * `output` - Optional output buffer for the hash digest:
    ///   - `None`: Only calculates and returns required buffer size
    ///   - `Some(buffer)`: Writes hash digest to buffer and returns bytes written
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size if `output` is `None`. The size is algorithm-specific:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small for the hash result
    /// - The underlying cryptographic operation fails
    /// - The session is invalid or has been closed
    /// - Platform cryptographic provider encounters an error
    ///
    /// # Buffer Management Pattern
    ///
    /// For safe buffer allocation without prior knowledge of hash size:
    /// 1. Call with `output = None` to get required size
    /// 2. Allocate buffer of returned size
    /// 3. Call again with allocated buffer to compute hash
    ///
    /// # Performance
    ///
    /// - Optimized for single-pass operation on complete data
    /// - May utilize hardware acceleration (SHA extensions, SIMD)
    /// - Efficient for data that fits in memory
    /// - No intermediate buffering or state management overhead
    pub fn hash<Algo: HsmHashOp>(
        session: &HsmSession,
        algo: &mut Algo,
        data: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Algo::Error> {
        algo.hash(session, data, output)
    }

    /// Performs single-operation hashing and returns the result as a vector.
    ///
    /// This is a convenience method that allocates a buffer and returns the hash
    /// digest as a `Vec<u8>`, avoiding the need for manual buffer management.
    /// It combines size query and hash computation in a single high-level operation.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session in which to perform the operation
    /// * `algo` - The hashing algorithm implementation (SHA-1, SHA-256, etc.)
    /// * `data` - Input data to hash. Can be any length.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the computed hash digest. The vector's
    /// length matches the algorithm's output size:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Memory allocation fails (out of memory)
    /// - The underlying cryptographic operation fails
    /// - The session is invalid or has been closed
    /// - Platform cryptographic provider encounters an error
    ///
    /// # Implementation Details
    ///
    /// This method internally:
    /// 1. Calls `hash` with `output = None` to query size
    /// 2. Allocates a vector of the required size
    /// 3. Calls `hash` again with the buffer to compute digest
    /// 4. Truncates the vector to actual bytes written
    /// 5. Returns the owned vector
    ///
    /// # Memory Allocation
    ///
    /// The method performs a single heap allocation for the output vector.
    /// The size is known in advance and deterministic for each algorithm.
    ///
    /// # Use Cases
    ///
    /// Preferred when:
    /// - Simplicity and ergonomics are more important than memory control
    /// - Hash digest needs to be owned and returned
    /// - Integrating with APIs that expect owned data
    /// - The additional allocation overhead is acceptable
    pub fn hash_vec<Algo: HsmHashOp>(
        session: &HsmSession,
        algo: &mut Algo,
        data: &[u8],
    ) -> Result<Vec<u8>, Algo::Error> {
        let hash_size = HsmHasher::hash(session, algo, data, None)?;
        let mut digest = vec![0u8; hash_size];
        let written = HsmHasher::hash(session, algo, data, Some(digest.as_mut_slice()))?;
        digest.truncate(written);
        Ok(digest)
    }

    /// Initializes a streaming hash context.
    ///
    /// This method creates a context for processing data in multiple chunks.
    /// The context maintains internal state across multiple update operations,
    /// allowing incremental hash computation without loading all data into memory.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to associate with this hash context.
    ///   The session provides resource management and scoping for the operation.
    /// * `algo` - The streaming hashing algorithm implementation. Must implement
    ///   the `HsmHashStreamingOp` trait, which provides streaming capabilities.
    ///
    /// # Returns
    ///
    /// Returns a hash context (type determined by the algorithm) that implements
    /// `HsmHashOpContext`. The context can be used to:
    /// - Call `update` repeatedly with data chunks
    /// - Call `finish` to produce the final hash digest
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying cryptographic provider fails to initialize
    /// - Memory allocation fails for context state
    /// - The session is invalid or has been closed
    /// - Platform-specific initialization errors occur
    ///
    /// # Context Lifecycle
    ///
    /// 1. **Initialization**: Call `hash_init` to create context
    /// 2. **Update Phase**: Call `update` any number of times with data chunks
    /// 3. **Finalization**: Call `finish` once to produce hash digest
    /// 4. **Cleanup**: Context is consumed by `finish` and should not be reused
    ///
    /// # State Management
    ///
    /// The returned context maintains:
    /// - Algorithm-specific working variables (intermediate state)
    /// - Buffer for partial blocks (incomplete block data)
    /// - Total message length counter (for proper padding)
    /// - Platform cryptographic provider handles
    ///
    /// # Memory Usage
    ///
    /// Context memory usage is minimal and fixed:
    /// - SHA-256: ~100 bytes (state + buffer)
    /// - SHA-512: ~200 bytes (state + buffer)
    /// - No accumulation of input data
    /// - Independent of total input size
    ///
    /// # Thread Safety
    ///
    /// The returned context is not thread-safe. Use from a single thread only.
    /// For concurrent hashing, create separate contexts per thread.
    pub fn hash_init<Algo: HsmHashStreamingOp>(
        session: HsmSession,
        algo: Algo,
    ) -> Result<Algo::Context, Algo::Error> {
        algo.hash_init(session)
    }
}
