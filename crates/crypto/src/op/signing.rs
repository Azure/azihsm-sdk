// Copyright (C) Microsoft Corporation. All rights reserved.

//! Traits for digital signature and verification operations.
//!
//! This module provides trait definitions for both single-operation and streaming
//! signature creation and verification. These traits abstract over different signature
//! algorithms (e.g., ECDSA, RSA-PSS, RSA-PKCS1v15, EdDSA) while providing a consistent interface.
//!
//! # Design
//!
//! The module provides two levels of signing APIs:
//!
//! - **Single-operation**: [`SignOp`] and [`VerifyOp`] for signing/verifying
//!   complete messages in a single call. Suitable for small messages or when all data
//!   is available at once.
//!
//! - **Streaming**: [`SignStreamingOp`] and [`VerifyStreamingOp`] with their
//!   respective contexts for processing data in chunks. Useful for large messages,
//!   streaming data, or when memory constraints prevent loading entire messages.

use super::*;

/// Trait for single-operation digital signature creation.
///
/// This trait provides a unified interface for creating digital signatures over
/// complete messages in a single operation. It's suitable for algorithms where
/// all data must be processed at once, or when the entire message fits in memory.
///
/// # Type Parameters
///
/// * `PrivKey` - The private key type implementing [`PrivateKey`]. Different signature
///   algorithms require different key types (e.g., ECC keys, RSA keys).
pub trait SignOp {
    /// The private key type used for this signing operation.
    type Key: SigningKey;

    /// Creates a digital signature over the provided data.
    ///
    /// # Arguments
    ///
    /// * `key` - The private key to use for signing
    /// * `data` - The data to sign (will be hashed internally if required by the algorithm)
    /// * `signature` - Optional output buffer for the signature. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The key is invalid or incompatible with this operation
    /// - The data length is invalid for this algorithm
    /// - The underlying cryptographic operation fails
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}

/// Trait for streaming digital signature creation.
///
/// This trait provides an interface for multi-step signature creation where
/// data is processed in chunks. This is useful for:
/// - Large files that don't fit in memory
/// - Streaming data sources (network, pipes)
/// - Progressive signing with intermediate hashing
///
/// # Type Parameters
///
/// * `PrivKey` - The private key type implementing [`PrivateKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`sign_init`](Self::sign_init) to create a context
/// 2. Update: Call [`update`](SignStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](SignStreamingOpContext::finish) to produce the signature
pub trait SignStreamingOp<'a> {
    /// The private key type used for this signing operation.
    type Key: SigningKey;

    /// The context type for streaming signature creation.
    type Context: SignStreamingOpContext<'a, Algo = Self>;

    /// Initializes a streaming signature creation context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state (typically a hash) across multiple
    /// [`update`](SignStreamingOpContext::update) calls until
    /// [`finish`](SignStreamingOpContext::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `key` - The private key to use for signing
    ///
    /// # Returns
    ///
    /// Returns a boxed context implementing [`SignStreamingOpContext`] that
    /// can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The underlying cryptographic provider fails to initialize
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError>;
}

/// Context for streaming digital signature creation.
///
/// This trait represents an active signing operation that processes data
/// incrementally. Contexts are created by [`SignStreamingOp::sign_init`]
/// and maintain internal state (typically a hash) across multiple updates.
///
/// # Lifecycle
///
/// 1. Create context via [`SignStreamingOp::sign_init`]
/// 2. Process data chunks with [`update`](Self::update) (can be called multiple times)
/// 3. Complete operation with [`finish`](Self::finish) to produce the signature
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe. Each context should be used from
/// a single thread.
pub trait SignStreamingOpContext<'a> {
    /// The signature algorithm type associated with this context.
    type Algo: SignStreamingOp<'a, Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state but does not produce output.
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
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalizes the signature creation operation.
    ///
    /// This method completes the operation, finalizes the internal hash, and
    /// produces the signature. The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer for the signature. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The underlying signature operation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// A new context must be created for additional signatures.
    fn finish(&mut self, signature: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Finalizes the operation and returns the signature as a vector.
    ///
    /// This is a convenience method that allocates the necessary output buffer,
    /// calls [`finish`](Self::finish), and returns the result as a `Vec<u8>`.
    ///
    /// # Returns
    ///
    /// Returns a vector containing the digital signature.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`finish`](Self::finish).
    fn finish_vec(&mut self) -> Result<Vec<u8>, CryptoError> {
        let required_size = self.finish(None)?;
        let mut signature = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut signature))?;
        signature.truncate(written_size);
        Ok(signature)
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

/// Trait for single-operation digital signature verification.
///
/// This trait provides a unified interface for verifying digital signatures over
/// complete messages in a single operation.
///
/// # Type Parameters
///
/// * `PubKey` - The public key type implementing [`PublicKey`]. Must correspond
///   to the private key type used for signing.
pub trait VerifyOp {
    /// The public key type used for this verification operation.
    type Key: VerificationKey;

    /// Verifies a digital signature over the provided data.
    ///
    /// # Arguments
    ///
    /// * `key` - The public key to use for verification
    /// * `data` - The data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature is malformed
    /// - The key is invalid or incompatible with this operation
    /// - The underlying cryptographic operation fails
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// Trait for streaming digital signature verification.
///
/// This trait provides an interface for multi-step signature verification where
/// data is processed in chunks. This is useful for:
/// - Large files that don't fit in memory
/// - Streaming data sources (network, pipes)
/// - Progressive verification with intermediate hashing
///
/// # Type Parameters
///
/// * `PubKey` - The public key type implementing [`PublicKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`verify_init`](Self::verify_init) to create a context
/// 2. Update: Call [`update`](VerifyStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](VerifyStreamingOpContext::finish) to verify the signature
pub trait VerifyStreamingOp<'a> {
    /// The public key type used for this verification operation.
    type Key: VerificationKey;

    /// The context type for streaming signature verification.
    type Context: VerifyStreamingOpContext<'a, Algo = Self>;

    /// Initializes a streaming signature verification context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context maintains internal state (typically a hash) across multiple
    /// [`update`](VerifyStreamingOpContext::update) calls until
    /// [`finish`](VerifyStreamingOpContext::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `key` - The public key to use for verification
    ///
    /// # Returns
    ///
    /// Returns a boxed context implementing [`VerifyStreamingOpContext`] that
    /// can be used to process data incrementally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this operation
    /// - The underlying cryptographic provider fails to initialize
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, CryptoError>;
}

/// Context for streaming digital signature verification.
///
/// This trait represents an active verification operation that processes data
/// incrementally. Contexts are created by [`VerifyStreamingOp::verify_init`]
/// and maintain internal state (typically a hash) across multiple updates.
///
/// # Lifecycle
///
/// 1. Create context via [`VerifyStreamingOp::verify_init`]
/// 2. Process data chunks with [`update`](Self::update) (can be called multiple times)
/// 3. Complete operation with [`finish`](Self::finish) to verify the signature
///
/// # Thread Safety
///
/// Contexts are not required to be thread-safe. Each context should be used from
/// a single thread.
pub trait VerifyStreamingOpContext<'a> {
    /// The signature algorithm type associated with this context.
    type Algo: VerifyStreamingOp<'a, Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state but does not produce output.
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
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalizes the signature verification operation.
    ///
    /// This method completes the operation, finalizes the internal hash, and
    /// verifies the signature against it. The context is consumed and cannot be
    /// used after this call.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature is malformed
    /// - The underlying verification operation fails
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// A new context must be created for additional verifications.
    fn finish(&mut self, signature: &[u8]) -> Result<bool, CryptoError>;

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

/// Trait for single-operation digital signature verification.
///
/// This trait provides a unified interface for verifying digital signatures over
/// complete messages in a single operation.
///
/// # Type Parameters
///
/// * `PubKey` - The public key type implementing [`PublicKey`]. Must correspond
///   to the private key type used for signing.
pub trait VerifyRecoverOp {
    /// The public key type used for this verification operation.
    type Key: VerificationKey;

    /// Verifies a digital signature over the provided data and recovers the signed message.
    ///
    /// # Arguments
    ///
    /// * `key` - The public key to use for verification
    /// * `signature` - The signature to verify
    /// * `output` - Optional buffer to receive the recovered message. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature is malformed
    /// - The key is invalid or incompatible with this operation
    /// - The underlying cryptographic operation fails
    fn verify_recover(
        &mut self,
        key: &Self::Key,
        signature: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}
