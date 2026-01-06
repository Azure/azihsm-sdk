// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based cryptographic hash function implementations for Linux systems.
//!
//! This module provides concrete implementations of various hash algorithms using
//! the OpenSSL cryptographic library. It serves as the Linux-specific backend
//! for the platform-agnostic hash interface defined in the parent module.
//!
//! # Supported Algorithms
//!
//! - **SHA-1**: Legacy hash function (cryptographically broken)
//! - **SHA-256**: Secure 256-bit hash from SHA-2 family
//! - **SHA-384**: Secure 384-bit hash from SHA-2 family
//! - **SHA-512**: Secure 512-bit hash from SHA-2 family
//!
//! # Implementation Strategy
//!
//! The module provides the `OsslHash` type that stores the selected hash algorithm
//! and corresponding OpenSSL `MessageDigest`. Instances can be created using the
//! `new()` constructor or convenient factory methods like `sha256()`.
//!
//! # Platform Integration
//!
//! - Leverages OpenSSL's optimized hash implementations
//! - Automatically benefits from hardware acceleration (AES-NI, etc.)
//! - Uses system-provided OpenSSL for security updates
//! - Provides memory-safe Rust wrappers around OpenSSL APIs
//!
//! # Performance
//!
//! OpenSSL implementations are highly optimized and include:
//! - Assembly-optimized code paths for various architectures
//! - Hardware acceleration when available
//! - Efficient memory management
//! - Vectorized operations for large data processing

use openssl::hash::*;
use openssl::md::*;

use super::*;

/// OpenSSL-based hash implementation.
///
/// This structure provides a hash implementation using OpenSSL APIs.
/// It stores the hash algorithm selection and the corresponding OpenSSL
/// `MessageDigest` for efficient hash operations.
#[derive(Clone)]
pub struct OsslHashAlgo {
    md: MessageDigest,
}

impl OsslHashAlgo {
    /// Creates a new instance of the OpenSSL hash implementation.
    ///
    /// Initializes the hash implementation with the specified algorithm and
    /// obtains the corresponding OpenSSL `MessageDigest`.
    ///
    /// # Arguments
    ///
    /// * `algo` - The hash algorithm to use
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance ready to perform hash operations.
    pub fn new(md: MessageDigest) -> Self {
        Self { md }
    }

    /// Creates a new SHA-1 hash instance.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-1 hashing.
    ///
    /// # Security Warning
    ///
    /// SHA-1 is cryptographically broken and should not be used for security-sensitive
    /// applications. Use SHA-256 or stronger algorithms instead.
    pub fn sha1() -> Self {
        Self::new(MessageDigest::sha1())
    }

    /// Creates a new SHA-256 hash instance.
    ///
    /// SHA-256 is part of the SHA-2 family and provides 256-bit hash values.
    /// It is recommended for most cryptographic applications.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-256 hashing.
    pub fn sha256() -> Self {
        Self::new(MessageDigest::sha256())
    }

    /// Creates a new SHA-384 hash instance.
    ///
    /// SHA-384 is part of the SHA-2 family and provides 384-bit hash values.
    /// It is a truncated version of SHA-512 and is suitable for high-security applications.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-384 hashing.
    pub fn sha384() -> Self {
        Self::new(MessageDigest::sha384())
    }

    /// Creates a new SHA-512 hash instance.
    ///
    /// SHA-512 is part of the SHA-2 family and provides 512-bit hash values.
    /// It is suitable for high-security applications requiring larger hash outputs.
    ///
    /// # Returns
    ///
    /// A new `OsslHash` instance configured for SHA-512 hashing.
    pub fn sha512() -> Self {
        Self::new(MessageDigest::sha512())
    }

    /// Returns the hash output size in bytes for this algorithm.
    ///
    /// This method provides the size of the hash digest produced by this
    /// hash algorithm without performing any cryptographic operations.
    ///
    /// # Returns
    ///
    /// The hash output size in bytes:
    /// - SHA-1: 20 bytes
    /// - SHA-256: 32 bytes
    /// - SHA-384: 48 bytes
    /// - SHA-512: 64 bytes
    pub fn size(&self) -> usize {
        self.md.size()
    }

    /// Returns the OpenSSL MessageDigest for this hash algorithm.
    ///
    /// # Returns
    ///
    /// The `MessageDigest` configured for this hash instance.
    pub(crate) fn message_digest(&self) -> MessageDigest {
        self.md
    }

    /// Returns a reference to the OpenSSL MdRef for this hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `MdRef` configured for this hash instance.
    pub(crate) fn md(&self) -> &MdRef {
        Md::from_nid(self.message_digest().type_()).unwrap()
    }

    /// Returns the DER digest algorithm identifier for this hash algorithm.
    ///
    /// # Returns
    ///
    /// The `DerDigestAlgo` corresponding to this hash algorithm.
    pub(crate) fn der_algo(&self) -> DerDigestAlgo {
        use openssl::nid::Nid;
        match self.md.type_() {
            Nid::SHA1 => DerDigestAlgo::Sha1,
            Nid::SHA256 => DerDigestAlgo::Sha256,
            Nid::SHA384 => DerDigestAlgo::Sha384,
            Nid::SHA512 => DerDigestAlgo::Sha512,
            _ => panic!("Unsupported hash algorithm for DER OID"),
        }
    }
}

/// Implementation of one-shot hash operations using OpenSSL.
///
/// This implementation provides both hash calculation and output size
/// determination through OpenSSL's optimized hash functions.
impl HashOp for OsslHashAlgo {
    /// Computes a hash using OpenSSL's optimized implementation.
    ///
    /// This method leverages OpenSSL's `hash::hash` function for one-shot
    /// hash computation. It handles both size queries and actual hash
    /// computation based on whether an output buffer is provided.
    ///
    /// # Implementation Details
    ///
    /// - Uses OpenSSL's optimized one-shot hash function
    /// - Validates output buffer size before computation
    /// - Copies result to user-provided buffer
    /// - Returns actual hash size regardless of operation mode
    ///
    /// # Buffer Management
    ///
    /// The method ensures the output buffer is large enough before performing
    /// the hash computation, preventing buffer overflows and ensuring safe
    /// operation.
    fn hash(&mut self, data: &[u8], hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        use openssl::hash;
        if let Some(hash) = hash {
            if hash.len() < self.md.size() {
                Err(CryptoError::HashBufferTooSmall)?;
            }
            let digest = hash::hash(self.md, data).map_err(|_| CryptoError::HashError)?;
            hash[..self.md.size()].copy_from_slice(&digest[..self.md.size()]);
        }
        Ok(self.md.size())
    }
}

impl HashStreamingOp for OsslHashAlgo {
    type Context = OsslHashAlgoContext;

    /// Initializes a new OpenSSL hash context for streaming operations.
    ///
    /// Creates a new OpenSSL `Hasher` instance configured with the
    /// appropriate `MessageDigest` for the algorithm. The context
    /// maintains internal state for incremental hash computation.
    ///
    /// # Context Initialization
    ///
    /// - Creates OpenSSL `Hasher` with algorithm-specific configuration
    /// - Stores the `MessageDigest` for later size queries
    /// - Handles OpenSSL initialization errors gracefully
    ///
    /// # Error Handling
    ///
    /// Returns `CryptoError::HashInitError` if OpenSSL context
    /// initialization fails, which may occur due to memory allocation
    /// failures or invalid algorithm configurations.
    fn hash_init(self) -> Result<Self::Context, CryptoError> {
        let context =
            openssl::hash::Hasher::new(self.md).map_err(|_| CryptoError::HashInitError)?;
        Ok(OsslHashAlgoContext {
            algo: self,
            hasher: context,
        })
    }
}

/// OpenSSL-based streaming hash context.
///
/// This structure maintains the state for streaming hash operations,
/// wrapping OpenSSL's `Hasher` and providing the necessary metadata
/// for proper operation.
///
/// # State Management
///
/// The context encapsulates:
/// - OpenSSL's internal hash state via `Hasher`
/// - Algorithm metadata via `MessageDigest`
/// - All necessary information for multi-step hash computation
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single
/// thread. OpenSSL's `Hasher` maintains internal state that could
/// be corrupted by concurrent access.
pub struct OsslHashAlgoContext {
    /// The hash algorithm instance.
    algo: OsslHashAlgo,
    /// OpenSSL hasher maintaining the algorithm state.
    hasher: openssl::hash::Hasher,
}

/// Implementation of streaming hash operations for OpenSSL contexts.
///
/// This implementation provides incremental hash computation through
/// OpenSSL's streaming interface, allowing efficient processing of
/// large datasets.
impl HashOpContext for OsslHashAlgoContext {
    /// The associated hash algorithm type.
    type Algo = OsslHashAlgo;

    /// Updates the hash state with new input data.
    ///
    /// This method feeds new data into OpenSSL's incremental hash
    /// computation engine. The data is processed immediately and
    /// the internal state is updated accordingly.
    ///
    /// # Implementation Details
    ///
    /// - Delegates directly to OpenSSL's `Hasher::update`
    /// - Handles OpenSSL errors and converts to `CryptoError`
    /// - Maintains hash state across multiple update calls
    /// - Optimized for processing data in chunks
    ///
    /// # Error Conditions
    ///
    /// Returns `CryptoError::HashUpdateError` if OpenSSL's update
    /// operation fails, which may indicate memory issues or
    /// corrupted context state.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.hasher
            .update(data)
            .map_err(|_| CryptoError::HashUpdateError)
    }

    /// Finalizes the hash computation and produces the final result.
    ///
    /// This method completes the hash computation by calling OpenSSL's
    /// finalization process, which applies the algorithm-specific padding
    /// and produces the final hash value.
    ///
    /// # Finalization Process
    ///
    /// 1. Validates output buffer size if provided
    /// 2. Calls OpenSSL's `Hasher::finish` to complete computation
    /// 3. Copies result to output buffer if provided
    /// 4. Returns the hash size regardless of operation mode
    ///
    /// # Buffer Management
    ///
    /// The method ensures the output buffer is sufficiently large to
    /// hold the complete hash result before attempting the finalization,
    /// preventing buffer overflows.
    ///
    /// # Context Consumption
    ///
    /// This method consumes the context by taking ownership (`self`),
    /// ensuring that the context cannot be accidentally reused after
    /// finalization, which would be a programming error.
    ///
    /// # Error Handling
    ///
    /// - `CryptoError::HashBufferTooSmall`: Output buffer insufficient
    /// - `CryptoError::HashFinalizeError`: OpenSSL finalization failed
    fn finish(&mut self, hash: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.algo.md.size();
        if let Some(hash) = hash {
            if hash.len() < len {
                Err(CryptoError::HashBufferTooSmall)?;
            }

            let digest = self
                .hasher
                .finish()
                .map_err(|_| CryptoError::HashFinishError)?;

            hash[..digest.len()].copy_from_slice(&digest);
        }

        Ok(len)
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
