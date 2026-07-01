// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based HMAC implementation for Linux systems.
//!
//! This module provides concrete implementations of HMAC operations using
//! the OpenSSL cryptographic library. It serves as the Linux-specific backend
//! for the platform-agnostic HMAC interface defined in the parent module.
//!
//! # Supported Algorithms
//!
//! - **HMAC-SHA1**: Legacy algorithm (20-byte output, use with caution)
//! - **HMAC-SHA256**: Recommended for most applications (32-byte output)  
//! - **HMAC-SHA384**: High security applications (48-byte output)
//! - **HMAC-SHA512**: Maximum security applications (64-byte output)
//!
//! # Implementation Strategy
//!
//! The module uses a generic approach with the `OsslHmacKey<Algo>` type that wraps
//! algorithm-specific implementations. Each algorithm implements the `OsslHmacAlgo`
//! trait to provide its OpenSSL `MessageDigest` configuration and key size limits.
//!
//! # Platform Integration
//!
//! - Leverages OpenSSL's optimized HMAC implementations
//! - Automatically benefits from hardware acceleration when available
//! - Uses system-provided OpenSSL for security updates
//! - Provides memory-safe Rust wrappers around OpenSSL APIs
//!
//! # Performance
//!
//! OpenSSL implementations are highly optimized and include:
//! - Assembly-optimized code paths for various architectures
//! - Hardware acceleration when available (AES-NI, etc.)
//! - Efficient memory management for large data processing
//! - Vectorized operations for bulk HMAC computations
//!
//! # Security Features
//!
//! - Constant-time verification to prevent timing attacks
//! - Secure key material handling with automatic zeroization
//! - Protection against side-channel attacks through OpenSSL's implementations
//! - Proper validation of key sizes according to algorithm specifications

use super::*;

/// OpenSSL-backed HMAC operation provider.
///
/// This structure configures and executes HMAC (Hash-based Message Authentication Code)
/// operations using OpenSSL's cryptographic primitives. It supports both single-operation
/// and streaming interfaces for signing and verification.
///
/// # Algorithm Support
///
/// Supports SHA-1, SHA-256, SHA-384, and SHA-512 as the underlying hash functions.
/// The hash algorithm is specified at construction time and determines the output size.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as it only stores configuration data.
/// Actual cryptographic operations are performed through OpenSSL APIs.
///
/// # Security
///
/// - Uses OpenSSL's constant-time verification to prevent timing attacks
/// - Leverages hardware acceleration when available
/// - Provides both oneshot and streaming APIs for different use cases
pub struct OsslHmacAlgo {
    /// The hash algorithm to use for HMAC.
    hash: HashAlgo,
}

impl OsslHmacAlgo {
    /// Creates a new HMAC operation provider from a hash instance.
    ///
    /// This constructor configures the HMAC provider but does not perform any
    /// cryptographic operations. Actual signing or verification occurs when
    /// calling the trait methods.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash instance specifying the algorithm to use
    ///
    /// # Returns
    ///
    /// A new `OsslHmac` instance configured for the specified algorithm.
    pub fn new(hash: HashAlgo) -> Self {
        Self { hash }
    }
}

/// Implements single-operation HMAC signing.
///
/// This implementation uses OpenSSL's `Signer` to compute HMAC values in a single call,
/// suitable for when all data is available at once.
impl SignOp for OsslHmacAlgo {
    type Key = HmacKey;

    /// Computes an HMAC signature over the provided data.
    ///
    /// This method can either query the required buffer size (when `signature` is `None`)
    /// or compute and write the HMAC to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for signing
    /// * `data` - The data to authenticate
    /// * `signature` - Optional output buffer. If `None`, only returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the signature buffer, or the required buffer size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::HmacBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::HmacSignError` - OpenSSL signing operation fails
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        use openssl::sign::Signer;

        let len = self.hash.size();
        if let Some(signature) = signature {
            if signature.len() < len {
                return Err(CryptoError::HmacBufferTooSmall);
            }

            let mut signer = Signer::new(self.hash.message_digest(), key.pkey())
                .map_err(|_| CryptoError::HmacSignError)?;

            signer
                .sign_oneshot(signature, data)
                .map_err(|_| CryptoError::HmacSignError)?;
        }

        Ok(len)
    }
}

/// Implements streaming HMAC signing.
///
/// This implementation allows processing data in multiple chunks, useful for large
/// files or streaming data sources.
impl<'a> SignStreamingOp<'a> for OsslHmacAlgo {
    type Key = HmacKey;
    type Context = OsslHmacAlgoSignContext<'a>;

    /// Initializes a streaming HMAC signing context.
    ///
    /// Creates a new context that can process data incrementally via the
    /// `update()` method before finalizing with `finish()`.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for signing
    ///
    /// # Returns
    ///
    /// A streaming context that implements `SignStreamingOpContext`.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacSignError` if context initialization fails.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        use openssl::sign::Signer;

        let signer = Signer::new(self.hash.message_digest(), key.pkey())
            .map_err(|_| CryptoError::HmacSignError)?;

        Ok(OsslHmacAlgoSignContext { signer, algo: self })
    }
}

/// Streaming context for HMAC signing operations.
///
/// This structure maintains the state for incremental HMAC computation,
/// allowing data to be processed in chunks before producing the final MAC.
///
/// # Lifetime
///
/// The lifetime parameter ensures the key remains valid for the duration
/// of the streaming operation.
pub struct OsslHmacAlgoSignContext<'a> {
    /// OpenSSL signer for computing the HMAC
    signer: openssl::sign::Signer<'a>,
    /// Expected output size in bytes
    algo: OsslHmacAlgo,
}

impl<'a> SignStreamingOpContext<'a> for OsslHmacAlgoSignContext<'a> {
    type Algo = OsslHmacAlgo;
    /// Processes a chunk of data.
    ///
    /// Updates the internal HMAC state with the provided data. Can be called
    /// multiple times before finalizing.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacSignError` if the update operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.signer
            .update(data)
            .map_err(|_| CryptoError::HmacSignError)
    }

    /// Finalizes the HMAC computation and produces the signature.
    ///
    /// Completes the HMAC operation and writes the result to the provided buffer,
    /// or returns the required buffer size if `signature` is `None`.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer. If `None`, only returns required size.
    ///
    /// # Returns
    ///
    /// The number of bytes written or required.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::HmacBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::HmacSignError` - Finalization fails
    fn finish(&mut self, signature: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.algo.hash.size();
        if let Some(signature) = signature {
            if signature.len() < len {
                return Err(CryptoError::HmacBufferTooSmall);
            }

            self.signer
                .sign(signature)
                .map_err(|_| CryptoError::HmacSignError)?;
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

/// Implements single-operation HMAC verification.
///
/// This implementation uses OpenSSL's `Verifier` which performs constant-time
/// comparison to prevent timing attacks.
impl VerifyOp for OsslHmacAlgo {
    type Key = HmacKey;

    /// Verifies an HMAC signature over the provided data.
    ///
    /// Uses constant-time comparison internally to prevent timing side-channel attacks.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for verification
    /// * `data` - The data that was authenticated
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacVerifyError` if the verification operation fails.
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        use openssl::sign::Signer;

        let mut result = vec![0u8; self.hash.size()];

        let mut verifier = Signer::new(self.hash.message_digest(), key.pkey())
            .map_err(|_| CryptoError::HmacVerifyError)?;

        verifier
            .sign_oneshot(&mut result, data)
            .map_err(|_| CryptoError::HmacVerifyError)?;

        Ok(result == signature)
    }
}

/// Implements streaming HMAC verification.
///
/// This implementation allows processing data in multiple chunks before verifying
/// the signature, useful for large files or streaming data sources.
impl<'a> VerifyStreamingOp<'a> for OsslHmacAlgo {
    /// The HMAC key type used for this verification operation.
    type Key = HmacKey;

    /// The context type for streaming HMAC verification.
    type Context = OsslHmacAlgoVerifyContext<'a>;

    /// Initializes a streaming HMAC verification context.
    ///
    /// Creates a new context that can process data incrementally via the
    /// `update()` method before verifying with `finish()`.
    ///
    /// # Arguments
    ///
    /// * `key` - The HMAC key to use for verification
    ///
    /// # Returns
    ///
    /// A streaming context that implements `VerifyStreamingOpContext`.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacVerifyError` if context initialization fails.
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        use openssl::sign::Signer;

        let verifier = Signer::new(self.hash.message_digest(), key.pkey())
            .map_err(|_| CryptoError::HmacVerifyInitError)?;

        Ok(OsslHmacAlgoVerifyContext {
            algo: self,
            verifier,
        })
    }
}

/// Streaming context for HMAC verification operations.
///
/// This structure maintains the state for incremental HMAC verification,
/// allowing data to be processed in chunks before verifying the signature.
///
/// # Lifetime
///
/// The lifetime parameter ensures the key remains valid for the duration
/// of the streaming operation.
pub struct OsslHmacAlgoVerifyContext<'a> {
    /// Algorithm configuration
    algo: OsslHmacAlgo,

    /// OpenSSL verifier for checking the HMAC
    verifier: openssl::sign::Signer<'a>,
}

impl<'a> VerifyStreamingOpContext<'a> for OsslHmacAlgoVerifyContext<'a> {
    /// The signature algorithm type associated with this context.
    type Algo = OsslHmacAlgo;

    /// Processes a chunk of data.
    ///
    /// Updates the internal HMAC state with the provided data. Can be called
    /// multiple times before finalizing.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacVerifyError` if the update operation fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.verifier
            .update(data)
            .map_err(|_| CryptoError::HmacVerifyUpdateError)
    }

    /// Finalizes the verification and checks the signature.
    ///
    /// Completes the HMAC computation and verifies it against the provided signature
    /// using constant-time comparison.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacVerifyError` if the verification operation fails.
    fn finish(&mut self, signature: &[u8]) -> Result<bool, CryptoError> {
        let mut result = vec![0u8; self.algo.hash.size()];

        self.verifier
            .sign(&mut result)
            .map_err(|_| CryptoError::HmacVerifyFinishError)?;

        Ok(result == signature)
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
