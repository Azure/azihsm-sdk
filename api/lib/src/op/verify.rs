// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// A zero-sized type providing a convenient interface for digital signature verification operations.
///
/// `HsmVerifier` wraps the [`VerifyOp`] and [`VerifyStreamingOp`] traits to provide
/// ergonomic static methods for verifying digital signatures. It supports both
/// single-shot verification (for complete messages in memory) and streaming verification
/// (for incremental processing of large or streaming data).
///
/// # Design
///
/// This is a zero-sized type that acts as a namespace for verification operations.
/// It delegates to the underlying trait implementations provided by specific
/// signature algorithms (e.g., ECDSA, RSA-PSS, RSA-PKCS1v15).
///
/// # Verification Algorithms
///
/// Different signature algorithms are supported through the type parameter `V`,
/// which must implement either [`VerifyOp`] for single-shot operations or
/// [`VerifyStreamingOp`] for streaming operations.
#[derive(Debug)]
pub struct HsmVerifier;

impl HsmVerifier {
    /// Verifies a digital signature over complete data in a single operation.
    ///
    /// This method is suitable for verifying signatures over complete messages that fit in memory.
    /// It processes the entire data buffer at once and verifies the signature.
    ///
    /// # Type Parameters
    ///
    /// * `V` - The verification algorithm implementing [`VerifyOp`]
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verification algorithm instance (may be zero-sized or carry configuration)
    /// * `key` - The public key to use for verification
    /// * `data` - The complete message data that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if the signature is invalid,
    /// or an error if the verification operation itself fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or incompatible with the verification algorithm
    /// - The data length is invalid for the algorithm
    /// - The signature format is incorrect
    /// - The underlying cryptographic operation fails
    ///
    /// # Performance
    ///
    /// For large messages, consider using [`verify_init`](Self::verify_init) instead
    /// to process data incrementally and reduce memory pressure.
    pub fn verify<Algo: HsmVerifyOp>(
        algo: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Algo::Error> {
        algo.verify(key, data, signature)
    }

    /// Initializes a streaming signature verification context.
    ///
    /// This method creates a context for processing data in multiple chunks,
    /// which is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data sources (network, pipes, iterators)
    /// - Progressive verification with intermediate hashing
    ///
    /// # Type Parameters
    ///
    /// * `V` - The verification algorithm implementing [`VerifyStreamingOp`]
    ///
    /// # Arguments
    ///
    /// * `verifier` - The verification algorithm instance
    /// * `key` - The public key to use for verification
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`VerifyStreamingOpContext`] that can be
    /// used to process data incrementally via [`update`](VerifyStreamingOpContext::update)
    /// and finalized with [`finish`](VerifyStreamingOpContext::finish).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this verification algorithm
    /// - The underlying cryptographic provider fails to initialize
    ///
    /// # Thread Safety
    ///
    /// The returned context is not thread-safe and should be used from a single thread.
    pub fn verify_init<Algo: HsmVerifyStreamingOp>(
        verifier: Algo,
        key: Algo::Key,
    ) -> Result<Algo::Context, Algo::Error> {
        verifier.verify_init(key)
    }
}
