// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ECDSA (Elliptic Curve Digital Signature Algorithm) implementation.
//!
//! This module provides ECDSA signature and verification operations using
//! elliptic curve cryptography. ECDSA combines hash functions with ECC
//! to create digital signatures that are both secure and compact.
//!
//! # Architecture
//!
//! The implementation follows a two-step approach:
//! 1. Hash the input data using the configured hash algorithm
//! 2. Sign or verify the hash using the underlying ECC primitives
//!
//! This separation ensures proper cryptographic design and allows
//! flexibility in hash algorithm selection.
//!
//! # Supported Operations
//!
//! - One-shot signing and verification for complete data
//! - Streaming signing and verification for incremental processing
//! - Support for any hash algorithm implementing required traits
//!
//! # Security Considerations
//!
//! - Hash algorithm choice affects overall security strength
//! - Private keys must be kept secure and never exposed
//! - Signatures are deterministic when using the same key and data
//! - Curve parameters determine the security level of signatures

use super::*;

/// ECDSA signature and verification engine.
///
/// This struct combines a hash algorithm with ECC operations to provide
/// complete ECDSA functionality. It acts as a bridge between hashing
/// and elliptic curve signature operations.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the hash algorithm reference
/// * `H` - Hash algorithm type supporting both one-shot and streaming operations
///
/// # Design
///
/// The ECDSA implementation is hash-algorithm agnostic, allowing users
/// to select appropriate hash functions based on their security requirements
/// and curve parameters. Common combinations include SHA-256 with P-256
/// and SHA-384 with P-384.
pub struct EcdsaAlgo {
    /// Reference to the hash algorithm used for message digesting
    hash: HashAlgo,
}

impl EcdsaAlgo {
    /// Creates a new ECDSA instance with the specified hash algorithm.
    ///
    /// Initializes an ECDSA engine that will use the provided hash algorithm
    /// for all signing and verification operations. The hash algorithm's
    /// output size should be compatible with the elliptic curve being used.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - Hash algorithm for message digesting
    ///
    /// # Returns
    ///
    /// A new ECDSA instance configured with the specified hash algorithm.
    pub fn new(hash: HashAlgo) -> Self {
        Self { hash }
    }
}

/// One-shot ECDSA signing implementation.
///
/// Provides the ability to sign complete data blocks in a single operation.
/// The implementation hashes the input data and then signs the resulting
/// hash using the provided ECC private key.
impl SignOp for EcdsaAlgo {
    /// ECC private key type used for signing operations.
    type Key = EccPrivateKey;

    /// Generates an ECDSA signature for the provided data.
    ///
    /// Performs the complete ECDSA signing operation in two steps:
    /// 1. Computes the hash of the input data using the configured hash algorithm
    /// 2. Signs the hash using the ECC private key
    ///
    /// # Arguments
    ///
    /// * `key` - ECC private key for signature generation
    /// * `data` - Input data to sign
    /// * `signature` - Optional output buffer for the signature
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written or required signature size
    /// * `Err(CryptoError)` - Signing operation failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hashing the input data fails
    /// - Output buffer is too small when provided
    /// - ECC signature generation fails
    /// - Key is invalid or incompatible with the operation
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let len = Hasher::hash(&mut self.hash, data, None)?;
        let mut hash_buf = vec![0u8; len];
        Hasher::hash(&mut self.hash, data, Some(&mut hash_buf))?;
        let mut sign_algo = EccAlgo {};
        Signer::sign(&mut sign_algo, key, &hash_buf, signature)
    }
}

/// Streaming ECDSA signing implementation.
///
/// Enables ECDSA signatures to be computed over data that arrives in
/// multiple chunks, without requiring the entire message in memory.
/// The hash is computed incrementally and then signed when finalized.
impl SignStreamingOp<'_> for EcdsaAlgo {
    /// ECC private key type used for streaming signing operations.
    type Key = EccPrivateKey;

    ///Context type for streaming signing operations.
    type Context = EcdsaAlgoSignContext;

    /// Initializes a streaming ECDSA signing context.
    ///
    /// Creates a context that can accept data in multiple chunks and
    /// produce an ECDSA signature when finalized. The hash state is
    /// initialized and ready to receive data.
    ///
    /// # Arguments
    ///
    /// * `key` - ECC private key for signature generation
    ///
    /// # Returns
    ///
    /// * `Ok(SignStreamingOpContext)` - Initialized signing context
    /// * `Err(CryptoError)` - Context initialization failure
    ///
    /// # Errors
    ///
    /// Returns an error if the hash streaming context cannot be initialized
    /// due to internal state issues or resource constraints.
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(EcdsaAlgoSignContext {
            ctx: Hasher::hash_init(self.hash.clone())?,
            algo: self,
            key,
        })
    }
}

/// ECDSA streaming signing context.
///
/// Maintains the state for computing ECDSA signatures over data that
/// arrives incrementally. The context holds both the hash computation
/// state and the private key reference needed for signature generation.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the private key reference
///
/// # Design
///
/// The context wraps a hash streaming context and defers signature
/// generation until all data has been processed, ensuring efficient
/// memory usage for large messages.
pub struct EcdsaAlgoSignContext {
    /// algo
    algo: EcdsaAlgo,
    /// Hash streaming context for incremental data processing
    ctx: HashAlgoContext,
    /// Reference to the ECC private key for signature generation
    key: EccPrivateKey,
}

impl SignStreamingOpContext<'_> for EcdsaAlgoSignContext {
    type Algo = EcdsaAlgo;
    /// Updates the hash computation with additional data.
    ///
    /// Incrementally processes the provided data chunk through the
    /// hash function. This can be called multiple times to process
    /// a message in parts.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to include in the signature
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Data processed successfully
    /// * `Err(CryptoError)` - Hash update failure
    ///
    /// # Errors
    ///
    /// Returns an error if the hash context update fails due to
    /// internal state issues or resource constraints.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ctx.update(data)
    }

    /// Finalizes the hash and generates the ECDSA signature.
    ///
    /// Completes the hash computation and signs the resulting digest
    /// using the ECC private key. This method consumes the hash context
    /// as it cannot be reused after finalization.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer for the signature
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written or required signature size
    /// * `Err(CryptoError)` - Finalization or signing failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hash finalization fails
    /// - Output buffer is too small when provided
    /// - ECC signature generation fails
    fn finish(&mut self, signature: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let len = self.ctx.finish(None)?;
        let mut hash_buf = vec![0u8; len];
        self.ctx.finish(Some(&mut hash_buf))?;
        let mut sign_algo = EccAlgo {};
        Signer::sign(&mut sign_algo, &self.key, &hash_buf, signature)
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

/// One-shot ECDSA verification implementation.
///
/// Provides the ability to verify ECDSA signatures for complete data
/// blocks in a single operation. The implementation hashes the input
/// data and verifies the signature against the resulting hash.
impl VerifyOp for EcdsaAlgo {
    /// ECC public key type used for verification operations.
    type Key = EccPublicKey;

    /// Verifies an ECDSA signature for the provided data.
    ///
    /// Performs the complete ECDSA verification operation in two steps:
    /// 1. Computes the hash of the input data using the configured hash algorithm
    /// 2. Verifies the signature against the hash using the ECC public key
    ///
    /// # Arguments
    ///
    /// * `key` - ECC public key for signature verification
    /// * `data` - Input data that was signed
    /// * `signature` - ECDSA signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Signature is valid for the data and key
    /// * `Ok(false)` - Signature is invalid
    /// * `Err(CryptoError)` - Verification process failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hashing the input data fails
    /// - Signature format is invalid
    /// - Public key is malformed or incompatible
    /// - Internal verification operation fails
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let len = Hasher::hash(&mut self.hash, data, None)?;
        let mut hash_buf = vec![0u8; len];
        Hasher::hash(&mut self.hash, data, Some(&mut hash_buf))?;
        let mut verify_algo = EccAlgo {};
        Verifier::verify(&mut verify_algo, key, &hash_buf, signature)
    }
}

/// Streaming ECDSA verification implementation.
///
/// Enables ECDSA signature verification for data that arrives in
/// multiple chunks, without requiring the entire message in memory.
/// The hash is computed incrementally and verified when finalized.
impl VerifyStreamingOp<'_> for EcdsaAlgo {
    /// ECC public key type used for streaming verification operations.
    type Key = EccPublicKey;

    /// Context type for streaming verification operations.
    type Context = EcdsaAlgoVerifyContext;

    /// Initializes a streaming ECDSA verification context.
    ///
    /// Creates a context that can accept data in multiple chunks and
    /// verify an ECDSA signature when finalized. The hash state is
    /// initialized and ready to receive data.
    ///
    /// # Arguments
    ///
    /// * `key` - ECC public key for signature verification
    ///
    /// # Returns
    ///
    /// * `Ok(VerifyStreamingOpContext)` - Initialized verification context
    /// * `Err(CryptoError)` - Context initialization failure
    ///
    /// # Errors
    ///
    /// Returns an error if the hash streaming context cannot be initialized
    /// due to internal state issues or resource constraints.
    fn verify_init<'b>(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(EcdsaAlgoVerifyContext {
            ctx: Hasher::hash_init(self.hash.clone())?,
            algo: self,
            key,
        })
    }
}

/// ECDSA streaming verification context.
///
/// Maintains the state for verifying ECDSA signatures over data that
/// arrives incrementally. The context holds both the hash computation
/// state and the public key reference needed for signature verification.
///
/// # Type Parameters
///
/// * `'a` - Lifetime of the public key reference
/// * `H` - Hash streaming context type
///
/// # Design
///
/// The context wraps a hash streaming context and defers signature
/// verification until all data has been processed, ensuring efficient
/// memory usage for large messages.
pub struct EcdsaAlgoVerifyContext {
    algo: EcdsaAlgo,
    /// Hash streaming context for incremental data processing
    ctx: HashAlgoContext,
    /// Reference to the ECC public key for signature verification
    key: EccPublicKey,
}

impl VerifyStreamingOpContext<'_> for EcdsaAlgoVerifyContext {
    /// The signature algorithm type associated with this context.
    type Algo = EcdsaAlgo;

    /// Updates the hash computation with additional data.
    ///
    /// Incrementally processes the provided data chunk through the
    /// hash function. This can be called multiple times to process
    /// a message in parts.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to include in the verification
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Data processed successfully
    /// * `Err(CryptoError)` - Hash update failure
    ///
    /// # Errors
    ///
    /// Returns an error if the hash context update fails due to
    /// internal state issues or resource constraints.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.ctx.update(data)
    }

    /// Finalizes the hash and verifies the ECDSA signature.
    ///
    /// Completes the hash computation and verifies the provided signature
    /// against the resulting digest using the ECC public key. This method
    /// consumes the hash context as it cannot be reused after finalization.
    ///
    /// # Arguments
    ///
    /// * `signature` - ECDSA signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Signature is valid for the processed data
    /// * `Ok(false)` - Signature is invalid
    /// * `Err(CryptoError)` - Finalization or verification failure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Hash finalization fails
    /// - Signature format is invalid
    /// - Internal verification operation fails
    fn finish(&mut self, signature: &[u8]) -> Result<bool, CryptoError> {
        let len = self.ctx.finish(None)?;
        let mut hash_buf = vec![0u8; len];
        self.ctx.finish(Some(&mut hash_buf))?;
        let mut verify_algo = EccAlgo {};
        Verifier::verify(&mut verify_algo, &self.key, &hash_buf, signature)
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
