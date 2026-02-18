// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
//! - **Single-operation**: [`HsmHashOp`] for computing hashes over complete messages
//!   in a single call. Suitable for small messages or when all data is available at once.
//!   Provides optimal performance for in-memory data with minimal API overhead.
//!
//! - **Streaming**: [`HsmHashStreamingOp`] and [`HsmHashOpContext`] for
//!   processing data in chunks. Useful for large messages, streaming data, or when
//!   memory constraints prevent loading entire messages. Enables incremental computation
//!   with constant memory usage regardless of total input size.
//!
//! # Hash Algorithms
//!
//! These traits support various cryptographic hash functions including:
//! - SHA-1 (deprecated for cryptographic use, provided for compatibility)
//! - SHA-256, SHA-384, SHA-512 (SHA-2 family)
//! - Future algorithms as needed (SHA-3, BLAKE2, etc.)
//!
//! # Design Principles
//!
//! ## Abstraction
//!
//! The traits provide algorithm-agnostic interfaces, allowing code to work with
//! any hash algorithm without modification. Type parameters enable compile-time
//! polymorphism without runtime overhead.
//!
//! ## Buffer Management
//!
//! All hash operations use the optional buffer pattern:
//! - Pass `None` to query output size
//! - Pass `Some(buffer)` to perform computation
//!
//! This eliminates guesswork and prevents buffer overflows.
//!
//! ## Error Handling
//!
//! Associated error types allow implementors to define algorithm-specific errors
//! while maintaining trait compatibility. All errors must implement `std::error::Error`.
//!
//! ## Zero-Copy
//!
//! Input data is accepted as slices (`&[u8]`), avoiding unnecessary copies.
//! Output is written directly to caller-provided buffers when possible.
//!
//! # Thread Safety
//!
//! - Algorithm types (implementing traits) are typically `Send + Sync`
//! - Individual contexts are not thread-safe and should be used from single threads
//! - Session handles may have platform-specific thread safety properties

use std::error::Error;

use super::*;

/// Trait for single-operation cryptographic hashing.
///
/// This trait provides a unified interface for computing cryptographic hashes over
/// complete messages in a single operation. It's suitable for scenarios where all
/// data is available in memory and can be processed in one pass.
///
/// # Design Pattern
///
/// The trait uses an optional output buffer pattern:
/// - When `output` is `None`: Returns the required output buffer size (hash length)
/// - When `output` is `Some`: Performs the actual hash computation
///
/// This allows callers to determine buffer requirements before performing
/// the actual computation, enabling safe buffer allocation without prior
/// knowledge of the algorithm's output size.
///
/// # Implementation Requirements
///
/// Implementors must:
/// - Produce cryptographically correct hash values per algorithm specifications
/// - Return accurate output size when `output` is `None` (deterministic per algorithm)
/// - Validate buffer sizes and return appropriate errors when buffers are too small
/// - Use platform-optimized implementations when available (OpenSSL, CNG, etc.)
/// - Handle edge cases (empty input, zero-length data) correctly
/// - Ensure deterministic output for identical inputs
///
/// # Performance Considerations
///
/// Implementations should:
/// - Leverage hardware acceleration when available (SHA extensions, SIMD)
/// - Minimize memory allocations (use provided output buffer directly)
/// - Optimize for single-pass operation over complete data
/// - Use platform cryptographic libraries that are regularly updated
///
/// # Security
///
/// Implementations must:
/// - Follow algorithm specifications exactly (no shortcuts)
/// - Clear sensitive data from memory when appropriate
/// - Use constant-time operations where timing attacks are a concern
/// - Validate all inputs before processing
pub trait HsmHashOp {
    type Error: Error;

    /// Computes a cryptographic hash of the input data.
    ///
    /// This method performs a complete hash computation in a single operation,
    /// processing all input data and producing the final hash digest.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session context. Provides session-scoped resources
    ///   and state. Some implementations may not use the session parameter.
    /// * `data` - The input data to hash. Can be any length from 0 bytes to
    ///   the maximum supported by the platform. Empty input is valid and produces
    ///   the hash of an empty message.
    /// * `output` - Optional output buffer for the hash digest:
    ///   - `None`: Only calculates and returns required buffer size without computation
    ///   - `Some(buffer)`: Computes hash and writes to buffer, returns bytes written
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size (hash length) if `output` is `None`. The size is deterministic
    /// for each algorithm:
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
    /// - Platform cryptographic provider encounters errors
    /// - Memory allocation fails in the underlying implementation
    ///
    /// # Determinism
    ///
    /// For any given algorithm and input data, this method must always produce
    /// the same hash output. The result is independent of:
    /// - Platform or architecture
    /// - Time of computation
    /// - Process or thread ID
    /// - Previous computations
    fn hash(
        &mut self,
        session: &HsmSession,
        data: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error>;
}

/// Trait for streaming cryptographic hash operations.
///
/// This trait provides an interface for multi-step hash computation where
/// data is processed in chunks. This is essential for:
/// - Large files that don't fit in memory (gigabytes to terabytes)
/// - Streaming data sources (network sockets, pipes, generators)
/// - Progressive hashing with intermediate state
/// - Memory-constrained environments
/// - Real-time processing scenarios
///
/// # Lifecycle
///
/// The streaming hash operation follows a three-phase lifecycle:
///
/// 1. **Initialize**: Call [`hash_init`](Self::hash_init) to create a context.
///    This allocates internal state and prepares for data processing.
///
/// 2. **Update**: Call [`update`](HsmHashOpContext::update) repeatedly with data chunks.
///    Each chunk can be any size. The context maintains state across calls.
///
/// 3. **Finalize**: Call [`finish`](HsmHashOpContext::finish) to produce the hash digest.
///    This applies padding, processes remaining data, and extracts the final hash.
///
/// # State Management
///
/// The context maintains internal hash state including:
/// - Algorithm-specific working variables (intermediate hash state)
/// - Buffered partial blocks (data that doesn't fill a complete block)
/// - Total input length counters (for proper padding computation)
/// - Platform-specific cryptographic provider handles
///
/// # Memory Efficiency
///
/// Streaming operations use constant memory regardless of input size:
/// - Context size is fixed per algorithm (~100-200 bytes)
/// - No accumulation of input data
/// - Only current block is buffered
/// - Ideal for processing data larger than available RAM
///
/// # Performance
///
/// Streaming can match or exceed single-shot performance:
/// - Large chunks (64KB+) provide optimal throughput
/// - Hardware acceleration applies to streaming operations
/// - Reduced memory pressure compared to loading all data
/// - Cache-friendly for large inputs
pub trait HsmHashStreamingOp {
    /// The associated hash algorithm type.
    type Error: Error;

    /// The context type for streaming hash operations.
    type Context: HsmHashOpContext<Algo = Self>;

    /// Initializes a streaming hash computation context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state across multiple
    /// [`update`](HsmHashOpContext::update) calls until
    /// [`finish`](HsmHashOpContext::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session to associate with this hash context.
    ///   The session provides resource scoping and lifetime management.
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`HsmHashOpContext`] that can be used to:
    /// - Process data incrementally via `update`
    /// - Produce the final hash digest via `finish`
    ///
    /// The context type is determined by the implementing algorithm and contains:
    /// - Algorithm-specific internal state
    /// - Buffer for partial block data
    /// - Message length tracking
    /// - Platform cryptographic provider handles
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying cryptographic provider fails to initialize
    /// - Memory allocation fails for context state
    /// - The session is invalid or has been closed
    /// - Platform-specific initialization errors occur
    /// - System resources are exhausted
    ///
    /// # Context Lifetime
    ///
    /// The context is independent once created:
    /// - Maintains its own internal state
    /// - Can outlive the algorithm instance that created it
    /// - Must be consumed by `finish` to produce results
    /// - Should not be cloned or shared across threads
    ///
    /// # Resource Management
    ///
    /// Context creation allocates minimal resources:
    /// - Fixed-size internal state (algorithm-dependent)
    /// - No heap allocation for input buffering
    /// - Platform provider handle (if applicable)
    /// - Typically 100-200 bytes total
    fn hash_init(self, session: HsmSession) -> Result<Self::Context, Self::Error>;
}

/// Context for streaming cryptographic hash operations.
///
/// This trait represents an active hash computation that processes data
/// incrementally. Contexts are created by [`HsmHashStreamingOp::hash_init`]
/// and maintain internal state across multiple updates.
///
/// # Lifecycle
///
/// 1. **Create**: Context is created via [`HsmHashStreamingOp::hash_init`].
///    Internal state is initialized according to algorithm specification.
///
/// 2. **Update**: Process data chunks with [`update`](Self::update). Can be called
///    any number of times with any chunk sizes. State is updated incrementally.
///
/// 3. **Finalize**: Complete operation with [`finish`](Self::finish) to produce
///    the hash digest. Context is consumed and cannot be reused.
///
/// # State Management
///
/// The context maintains:
/// - Internal algorithm state (e.g., hash state variables, working registers)
/// - Buffered partial blocks (data that doesn't complete a block)
/// - Total input length (for proper padding during finalization)
/// - Platform-specific provider handles (OpenSSL context, CNG handle, etc.)
///
/// # Block Processing
///
/// Hash algorithms process data in fixed-size blocks:
/// - SHA-1, SHA-256: 512-bit (64-byte) blocks
/// - SHA-384, SHA-512: 1024-bit (128-byte) blocks
///
/// The context automatically:
/// - Buffers incomplete blocks across update calls
/// - Processes complete blocks immediately for efficiency
/// - Handles boundary conditions between chunks
///
/// # Memory Characteristics
///
/// - **Size**: Fixed, typically 100-200 bytes
/// - **Allocation**: Stack or heap, implementation-defined
/// - **Input buffering**: Only one block maximum
/// - **Scalability**: Constant memory regardless of total input size
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe:
/// - Use each context from a single thread only
/// - Do not share contexts between threads
/// - Create separate contexts for concurrent operations
/// - Internal state is not protected by synchronization
///
/// # Implementation Notes
///
/// Implementors should:
/// - Maintain exact algorithm state per specification
/// - Handle partial blocks correctly across updates
/// - Support arbitrary chunk sizes efficiently
/// - Clear sensitive state on drop (if applicable)
pub trait HsmHashOpContext {
    /// The associated hash algorithm type.
    type Algo: HsmHashStreamingOp<Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state. The data is processed according
    /// to the hash algorithm's block size, with partial blocks buffered internally.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process. Can be any size from 0 bytes to gigabytes.
    ///   Empty slices are valid no-ops.
    ///
    /// # Behavior
    ///
    /// The method processes data as follows:
    /// 1. Combines input with any buffered partial block from previous updates
    /// 2. Processes as many complete blocks as possible
    /// 3. Buffers any remaining partial block for next update
    /// 4. Updates internal hash state accordingly
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation has already been finalized (context consumed)
    /// - The underlying hash operation fails
    /// - Memory allocation fails (if implementation requires)
    /// - Platform cryptographic provider reports an error
    ///
    /// # Performance
    ///
    /// - Optimized for processing data in chunks of any size
    /// - Automatically handles block-level buffering
    /// - Utilizes platform-specific optimizations (SIMD, vectorization)
    /// - May leverage hardware acceleration (Intel SHA, ARM SHA extensions)
    /// - Larger chunks generally provide better throughput (less overhead)
    ///
    /// # Chunk Sizing
    ///
    /// Optimal chunk sizes depend on the use case:
    /// - **Small chunks** (< 1KB): Higher per-byte overhead, suitable for streaming
    /// - **Medium chunks** (4KB-64KB): Good balance for most scenarios
    /// - **Large chunks** (> 64KB): Maximum throughput, minimal overhead
    /// - **Block-aligned**: Multiples of block size (64 or 128 bytes) may optimize
    ///
    /// # State Updates
    ///
    /// After this call:
    /// - Internal hash state reflects all data processed so far
    /// - Context can accept more data via additional `update` calls
    /// - Context can be finalized via `finish` to produce the hash
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmHashStreamingOp>::Error>;

    /// Finalizes the hash computation and produces the digest.
    ///
    /// This method completes the hash computation by:
    /// 1. Processing any remaining buffered data
    /// 2. Applying padding according to the algorithm specification (Merkle-Damgård)
    /// 3. Producing the final hash digest from internal state
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer for the hash digest:
    ///   - `None`: Only calculates and returns required buffer size
    ///   - `Some(buffer)`: Computes hash and writes to buffer
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the output buffer, or the required
    /// buffer size (hash length) if `output` is `None`. The size is deterministic
    /// per algorithm:
    /// - SHA-1: 20 bytes (160 bits)
    /// - SHA-256: 32 bytes (256 bits)
    /// - SHA-384: 48 bytes (384 bits)
    /// - SHA-512: 64 bytes (512 bits)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small for the hash result
    /// - The underlying finalization operation fails
    /// - Platform cryptographic provider reports an error
    /// - Context has already been finalized
    ///
    /// # Padding Process
    ///
    /// The finalization applies algorithm-specific padding:
    /// 1. Append bit '1' to the message
    /// 2. Append '0' bits until length ≡ 448 (mod 512) or 896 (mod 1024)
    /// 3. Append message length as 64-bit or 128-bit integer
    /// 4. Process final padded block(s)
    /// 5. Extract hash value from internal state
    ///
    /// # Context Consumption
    ///
    /// After calling this method:
    /// - The context internal state is finalized
    /// - Context cannot be reused for additional updates
    /// - Attempting to call `update` or `finish` again is an error
    /// - Create a new context for additional hash computations
    ///
    /// # Determinism
    ///
    /// For identical input sequences (regardless of chunking), the result is always
    /// the same:
    /// - Chunk boundaries don't affect output
    /// - Update call frequency is irrelevant
    /// - Platform-independent results (standardized algorithms)
    ///
    /// # Buffer Safety
    ///
    /// Call pattern for safe buffer allocation:
    /// 1. Call with `output = None` to query size
    /// 2. Allocate buffer of returned size
    /// 3. Call again with buffer to get hash
    ///
    /// Note: After calling with `None`, the context should not be reused.
    /// This is a limitation of the current API design.
    fn finish(
        &mut self,
        output: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmHashStreamingOp>::Error>;

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
    /// matches the hash algorithm's output size:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The underlying finalization operation fails
    /// - Memory allocation fails (out of memory)
    /// - Platform cryptographic provider reports an error
    /// - Context has already been finalized
    ///
    /// # Implementation Details
    ///
    /// This method performs the following steps:
    /// 1. Calls `finish(None)` to query required size
    /// 2. Allocates a vector of the required size
    /// 3. Calls `finish(Some(buffer))` to compute hash
    /// 4. Truncates vector to actual bytes written
    /// 5. Returns owned vector
    ///
    /// # Memory Allocation
    ///
    /// - Single heap allocation for output vector
    /// - Size is deterministic and known in advance
    /// - No reallocation occurs during computation
    ///
    /// # Use Cases
    ///
    /// Prefer this method when:
    /// - Simplicity is more important than control
    /// - Hash needs to be owned and returned
    /// - Integrating with APIs expecting owned data
    /// - Additional allocation overhead is acceptable
    ///
    /// # Context Consumption
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// Create a new context for additional hash computations.
    fn finish_vec(&mut self) -> Result<Vec<u8>, <Self::Algo as HsmHashStreamingOp>::Error> {
        let hash_size = self.finish(None)?;
        let mut hash_buf = vec![0u8; hash_size];
        let written = self.finish(Some(&mut hash_buf))?;
        hash_buf.truncate(written);
        Ok(hash_buf)
    }
}
