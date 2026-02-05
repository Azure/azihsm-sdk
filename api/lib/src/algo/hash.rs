// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic hash algorithm implementations.
//!
//! This module provides HSM-compatible hash algorithms including SHA-1, SHA-256,
//! SHA-384, and SHA-512. It supports both single-shot and streaming hash operations
//! through traits defined in the parent module.
//!
//! # Supported Algorithms
//!
//! - **SHA-1**: 160-bit hash (deprecated for cryptographic use)
//! - **SHA-256**: 256-bit hash from the SHA-2 family
//! - **SHA-384**: 384-bit hash from the SHA-2 family
//! - **SHA-512**: 512-bit hash from the SHA-2 family
//!
//! # Operation Modes
//!
//! The module provides two operation modes:
//!
//! ## Single-shot Operations
//!
//! Complete hash computation in a single call, suitable for data
//! that fits in memory. This mode is optimal for small to medium-sized
//! data where all input is available at once.
//!
//! ## Streaming Operations
//!
//! Incremental hash computation through multiple update calls,
//! suitable for large data or streaming sources. This mode enables
//! memory-efficient processing of data that doesn't fit in memory
//! or arrives over time.
//!
//! # Platform Integration
//!
//! Hash operations delegate to platform-specific cryptographic libraries:
//! - Linux: OpenSSL implementations with hardware acceleration
//! - Windows: CNG (Cryptography Next Generation) APIs
//!
//! # Thread Safety
//!
//! Hash algorithm instances are safe to clone and use across threads.
//! However, individual hash contexts are not thread-safe and should
//! be used from a single thread.

use azihsm_crypto as crypto;

use super::*;

/// Enumeration of supported hash algorithms.
///
/// This enum represents the hash algorithms supported by the HSM,
/// providing compile-time type safety for algorithm selection. Each
/// variant corresponds to a specific SHA (Secure Hash Algorithm)
/// implementation with different output sizes and security properties.
///
/// # Algorithm Properties
///
/// | Algorithm | Output Size | Block Size | Security Level |
/// |-----------|-------------|------------|----------------|
/// | SHA-1     | 160 bits    | 512 bits   | Broken         |
/// | SHA-256   | 256 bits    | 512 bits   | 128 bits       |
/// | SHA-384   | 384 bits    | 1024 bits  | 192 bits       |
/// | SHA-512   | 512 bits    | 1024 bits  | 256 bits       |
///
/// # Security Considerations
///
/// - **SHA-1**: Cryptographically broken due to collision attacks. Use only
///   for non-security purposes like checksums or legacy system compatibility.
/// - **SHA-256**: Provides adequate security for most applications. Widely
///   supported and efficient.
/// - **SHA-384**: Truncated SHA-512 variant offering higher security margin.
/// - **SHA-512**: Provides the highest security level and is recommended for
///   applications requiring long-term cryptographic strength.
///
/// # Performance
///
/// Performance varies by algorithm and platform:
/// - SHA-256 is generally fastest on 32-bit architectures
/// - SHA-512 is often faster on 64-bit architectures
/// - Hardware acceleration (AES-NI, SHA extensions) significantly improves performance
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HsmHashAlgo {
    /// SHA-1 hash algorithm (160-bit output).
    ///
    /// SHA-1 produces a 160-bit (20-byte) hash value from arbitrary input data.
    /// It was designed by the NSA and published by NIST in 1995.
    ///
    /// **Security Warning**: SHA-1 is cryptographically broken. Practical collision
    /// attacks have been demonstrated (SHAttered attack, 2017). Do not use for:
    /// - Digital signatures
    /// - Certificate validation
    /// - Password hashing
    /// - Any security-critical application
    ///
    /// Acceptable uses are limited to:
    /// - Non-cryptographic checksums
    /// - Legacy system compatibility
    /// - Git commit hashes (in non-adversarial contexts)
    Sha1,
    /// SHA-256 hash algorithm (256-bit output).
    ///
    /// SHA-256 is part of the SHA-2 family and produces a 256-bit (32-byte) hash.
    /// It was designed by the NSA and published by NIST in 2001 as part of FIPS 180-2.
    ///
    /// **Characteristics**:
    /// - Block size: 512 bits
    /// - Collision resistance: 128-bit security level
    /// - Widely supported across platforms and applications
    /// - Optimal performance on 32-bit architectures
    ///
    /// **Recommended for**:
    /// - General-purpose cryptographic hashing
    /// - Digital signatures
    /// - Certificate generation
    /// - Integrity verification
    /// - Password-based key derivation (with proper KDFs)
    Sha256,
    /// SHA-384 hash algorithm (384-bit output).
    ///
    /// SHA-384 is part of the SHA-2 family and produces a 384-bit (48-byte) hash.
    /// It is a truncated version of SHA-512, using the same internal algorithm
    /// but with different initial values and truncated output.
    ///
    /// **Characteristics**:
    /// - Block size: 1024 bits
    /// - Collision resistance: 192-bit security level
    /// - Based on SHA-512 internals (64-bit word operations)
    /// - Efficient on 64-bit architectures
    ///
    /// **Recommended for**:
    /// - High-security applications requiring larger hash outputs
    /// - Systems needing intermediate security between SHA-256 and SHA-512
    /// - Cryptographic protocols specifying 384-bit hashes
    /// - Applications with 192-bit security requirements
    Sha384,
    /// SHA-512 hash algorithm (512-bit output).
    ///
    /// SHA-512 is part of the SHA-2 family and produces a 512-bit (64-byte) hash.
    /// It uses 64-bit word operations and is often faster than SHA-256 on
    /// 64-bit architectures despite producing longer output.
    ///
    /// **Characteristics**:
    /// - Block size: 1024 bits
    /// - Collision resistance: 256-bit security level
    /// - Uses 64-bit arithmetic (efficient on modern 64-bit CPUs)
    /// - Larger security margin than SHA-256
    ///
    /// **Recommended for**:
    /// - Maximum security applications
    /// - Long-term data integrity (archival systems)
    /// - High-security digital signatures
    /// - Systems requiring 256-bit security level
    /// - Performance-critical applications on 64-bit systems
    Sha512,
}

impl HsmHashAlgo {
    /// Creates a new SHA-1 hash algorithm instance.
    ///
    /// # Returns
    ///
    /// An `HsmHashAlgo` configured for SHA-1 hashing.
    ///
    /// # Security Warning
    ///
    /// SHA-1 is cryptographically broken and should not be used for security-sensitive
    /// applications. This method is provided for legacy compatibility only.
    pub fn sha1() -> Self {
        HsmHashAlgo::Sha1
    }

    /// Creates a new SHA-256 hash algorithm instance.
    ///
    /// SHA-256 is part of the SHA-2 family and provides 256-bit hash values.
    /// It is recommended for most cryptographic applications.
    ///
    /// # Returns
    ///
    /// An `HsmHashAlgo` configured for SHA-256 hashing.
    pub fn sha256() -> Self {
        HsmHashAlgo::Sha256
    }

    /// Creates a new SHA-384 hash algorithm instance.
    ///
    /// SHA-384 is part of the SHA-2 family and provides 384-bit hash values.
    /// It is a truncated version of SHA-512 and is suitable for high-security applications.
    ///
    /// # Returns
    ///
    /// An `HsmHashAlgo` configured for SHA-384 hashing.
    pub fn sha384() -> Self {
        HsmHashAlgo::Sha384
    }

    /// Creates a new SHA-512 hash algorithm instance.
    ///
    /// SHA-512 is part of the SHA-2 family and provides 512-bit hash values.
    /// It is suitable for high-security applications requiring larger hash outputs.
    ///
    /// # Returns
    ///
    /// An `HsmHashAlgo` configured for SHA-512 hashing.
    pub fn sha512() -> Self {
        HsmHashAlgo::Sha512
    }
}

/// Implementation of single-shot hash operations.
///
/// This implementation provides one-shot hashing where all data is processed
/// in a single call. It delegates to the underlying cryptographic library
/// for platform-optimized implementations.
impl HsmHashOp for HsmHashAlgo {
    type Error = HsmError;

    /// Computes a cryptographic hash of the input data in a single operation.
    ///
    /// This method performs a complete hash computation on the provided data,
    /// producing the hash digest in one call. The implementation uses platform-
    /// optimized cryptographic libraries and may leverage hardware acceleration
    /// when available.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session (unused in current implementation)
    /// * `data` - The input data to hash (can be any length)
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output buffer, or required buffer
    ///   size if `output` is `None`. The size depends on the selected algorithm.
    /// * `Err(HsmError::InternalError)` - If the underlying cryptographic operation
    ///   fails due to invalid parameters or system errors.
    ///
    /// # Hash Output Sizes
    ///
    /// The output size is deterministic for each algorithm:
    /// - SHA-1: 20 bytes (160 bits)
    /// - SHA-256: 32 bytes (256 bits)
    /// - SHA-384: 48 bytes (384 bits)
    /// - SHA-512: 64 bytes (512 bits)
    ///
    /// # Buffer Management
    ///
    /// Call this method twice for safe buffer allocation:
    /// 1. First call with `output = None` to get required size
    /// 2. Allocate buffer of returned size
    /// 3. Second call with allocated buffer to get hash
    ///
    /// # Performance
    ///
    /// - Optimized for single-pass operation on complete data
    /// - Uses platform-specific SIMD instructions when available
    /// - May utilize CPU SHA extensions for hardware acceleration
    fn hash(
        &mut self,
        session: &HsmSession,
        data: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        let _ = session; // session is unused in this implementation
        let mut algo = crypto::HashAlgo::from(*self);
        crypto::Hasher::hash(&mut algo, data, output).map_hsm_err(HsmError::InternalError)
    }
}

/// Implementation of streaming hash operations.
///
/// This implementation provides incremental hashing where data can be processed
/// in multiple chunks. Useful for large data sets or streaming sources.
impl HsmHashStreamingOp for HsmHashAlgo {
    type Error = HsmError;
    type Context = HsmHashContext;

    /// Initializes a streaming hash computation context.
    ///
    /// Creates a new context for processing data incrementally through multiple
    /// [`update`](HsmHashOpContext::update) calls followed by a final
    /// [`finish`](HsmHashOpContext::finish) call. This approach is memory-efficient
    /// for large data sets and supports real-time processing of streaming data.
    ///
    /// # Arguments
    ///
    /// * `session` - The HSM session (unused in current implementation)
    ///
    /// # Returns
    ///
    /// * `Ok(HsmHashContext)` - An initialized hash context ready for streaming operations.
    ///   The context maintains internal state including algorithm parameters, working
    ///   buffers, and partial block data.
    /// * `Err(HsmError::InternalError)` - If context initialization fails due to memory
    ///   allocation errors or platform cryptographic library initialization failures.
    ///
    /// # Lifecycle
    ///
    /// 1. **Initialize**: Call `hash_init` to create the context
    /// 2. **Update**: Call `update` repeatedly with data chunks (any size, any number of calls)
    /// 3. **Finalize**: Call `finish` once to produce the final hash digest
    ///
    /// # Context State
    ///
    /// The context maintains:
    /// - Internal algorithm state variables (working registers)
    /// - Buffer for partial blocks (data not yet processed)
    /// - Total byte counter for proper padding
    /// - Platform-specific cryptographic provider handles
    ///
    /// # Memory Usage
    ///
    /// Context size is minimal and algorithm-dependent:
    /// - SHA-256: ~100 bytes (state + 64-byte buffer)
    /// - SHA-512: ~200 bytes (state + 128-byte buffer)
    fn hash_init(self, session: HsmSession) -> Result<Self::Context, Self::Error> {
        let _ = session; // session is unused in this implementation
        let algo = crypto::HashAlgo::from(self);
        let context = crypto::Hasher::hash_init(algo).map_hsm_err(HsmError::InternalError)?;
        Ok(HsmHashContext { context })
    }
}

/// Context for streaming hash operations.
///
/// This structure maintains the state of an ongoing hash computation,
/// allowing data to be processed incrementally through multiple calls.
/// It wraps the platform-specific cryptographic context and provides
/// a safe, high-level interface for incremental hashing.
///
/// # State Management
///
/// The context maintains:
/// - Algorithm-specific working variables (intermediate hash state)
/// - Partial block buffer for data that doesn't fill a complete block
/// - Message length counter for final padding computation
/// - Platform-specific cryptographic provider handles
///
/// # Block Processing
///
/// Hash algorithms process data in fixed-size blocks:
/// - SHA-1, SHA-256: 512-bit (64-byte) blocks
/// - SHA-384, SHA-512: 1024-bit (128-byte) blocks
///
/// The context automatically buffers partial blocks and processes complete
/// blocks as soon as enough data is available.
///
/// # Memory Efficiency
///
/// The context uses minimal memory:
/// - Only stores current algorithm state
/// - No accumulation of input data
/// - Fixed-size internal buffers regardless of input size
///
/// # Thread Safety
///
/// This context is not thread-safe. Each context must be used exclusively
/// by a single thread. For concurrent hashing:
/// - Create separate contexts for each thread
/// - Use message passing if results need to be combined
/// - Consider data parallelism strategies for large datasets
///
/// # Lifecycle
///
/// Created by [`HsmHashAlgo::hash_init`], used through [`HsmHashOpContext`] methods,
/// and consumed by [`finish`](HsmHashOpContext::finish). After finalization, the
/// context should not be reused.
pub struct HsmHashContext {
    /// The underlying cryptographic hash context.
    context: crypto::HashAlgoContext,
}

/// Implementation of streaming hash context operations.
///
/// This implementation provides the methods for incremental hash computation,
/// delegating to the underlying cryptographic library for efficient processing.
impl HsmHashOpContext for HsmHashContext {
    type Algo = HsmHashAlgo;

    /// Processes a chunk of data in the streaming hash operation.
    ///
    /// This method can be called multiple times to feed data incrementally.
    /// Each call updates the internal hash state without producing output.
    /// The method automatically handles block-level buffering, processing
    /// complete blocks immediately and storing partial blocks for later.
    ///
    /// # Arguments
    ///
    /// * `data` - The data chunk to process. Can be any size from 0 bytes
    ///   to gigabytes. Empty slices are valid and do nothing.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Data was successfully processed and internal state updated.
    ///   No output is produced; call [`finish`](Self::finish) to get the hash.
    /// * `Err(HsmError::InternalError)` - If the update operation fails due to
    ///   platform cryptographic library errors or memory issues.
    ///
    /// # Block Processing
    ///
    /// Data is processed in algorithm-specific block sizes:
    /// - If internal buffer + new data >= block size: Process complete blocks
    /// - If data doesn't complete a block: Store in internal buffer
    /// - Multiple blocks in a single call are processed efficiently
    ///
    /// # Performance Considerations
    ///
    /// - Larger chunks generally provide better performance (less overhead)
    /// - Block-aligned inputs (multiples of 64 or 128 bytes) are most efficient
    /// - The implementation uses platform-specific optimizations:
    ///   * SIMD instructions (AVX, AVX2, AVX-512)
    ///   * Hardware SHA extensions (Intel SHA, ARM SHA)
    ///   * Vectorized implementations from OpenSSL/CNG
    ///
    /// # Call Frequency
    ///
    /// The method can be called any number of times:
    /// - Once with all data: Equivalent to single-shot operation
    /// - Many times with small chunks: Suitable for streaming
    /// - Mixed chunk sizes: Works correctly with any pattern
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmHashStreamingOp>::Error> {
        use crypto::HashOpContext;
        self.context
            .update(data)
            .map_hsm_err(HsmError::InternalError)
    }

    /// Finalizes the hash computation and produces the digest.
    ///
    /// This method completes the hash computation by:
    /// 1. Processing any remaining buffered data
    /// 2. Applying algorithm-specific padding (adding length and pad bits)
    /// 3. Producing the final hash digest from internal state
    ///
    /// The padding scheme follows the Merkle-Damgård construction:
    /// - Append a '1' bit followed by '0' bits
    /// - Add message length as 64-bit or 128-bit integer
    /// - Ensure total length is a multiple of block size
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, only calculates required size.
    ///   Buffer must be at least as large as the algorithm's output size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output buffer, or required buffer
    ///   size if `output` is `None`. The size is constant for each algorithm and
    ///   independent of input data length.
    /// * `Err(HsmError::InternalError)` - If the finalization operation fails due to:
    ///   * Invalid context state (already finalized)
    ///   * Platform cryptographic library errors
    ///   * Output buffer too small (when buffer is provided)
    ///
    /// # Hash Output Sizes
    ///
    /// The output size is deterministic and algorithm-specific:
    /// - SHA-1: 20 bytes (160 bits)
    /// - SHA-256: 32 bytes (256 bits)
    /// - SHA-384: 48 bytes (384 bits)
    /// - SHA-512: 64 bytes (512 bits)
    ///
    /// # Buffer Management
    ///
    /// For safe buffer allocation:
    /// 1. Call with `output = None` to get required size
    /// 2. Allocate buffer of returned size
    /// 3. Call again with buffer to get hash digest
    ///
    /// # Context Consumption
    ///
    /// After calling this method:
    /// - The context internal state is finalized
    /// - Do not call `update` or `finish` again on the same context
    /// - Create a new context for additional hash computations
    /// - Attempting to reuse the context results in undefined behavior
    ///
    /// # Determinism
    ///
    /// For identical input sequences, the same hash is always produced:
    /// - Same data in same order → same hash
    /// - Chunk boundaries don't affect output
    /// - Platform-independent results (standardized algorithms)
    fn finish(
        &mut self,
        output: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmHashStreamingOp>::Error> {
        use crypto::HashOpContext;
        self.context
            .finish(output)
            .map_hsm_err(HsmError::InternalError)
    }
}

/// Converts an HSM hash algorithm to the underlying cryptographic library's hash algorithm.
///
/// This implementation allows seamless conversion between the HSM API layer and the
/// cryptographic implementation layer, mapping each HSM algorithm variant to its
/// corresponding platform-optimized implementation.
impl From<HsmHashAlgo> for crypto::HashAlgo {
    /// Converts an `HsmHashAlgo` to a `crypto::HashAlgo`.
    ///
    /// # Arguments
    ///
    /// * `algo` - The HSM hash algorithm to convert
    ///
    /// # Returns
    ///
    /// The corresponding cryptographic library hash algorithm instance,
    /// ready for use with the underlying hash operations.
    fn from(algo: HsmHashAlgo) -> Self {
        match algo {
            HsmHashAlgo::Sha1 => crypto::HashAlgo::sha1(),
            HsmHashAlgo::Sha256 => crypto::HashAlgo::sha256(),
            HsmHashAlgo::Sha384 => crypto::HashAlgo::sha384(),
            HsmHashAlgo::Sha512 => crypto::HashAlgo::sha512(),
        }
    }
}
