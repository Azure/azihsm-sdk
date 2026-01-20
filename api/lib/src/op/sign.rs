// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

/// A zero-sized type providing a convenient interface for digital signature operations.
///
/// `HsmSigner` wraps the [`SignOp`] and [`SignStreamingOp`] traits to provide
/// ergonomic static methods for creating digital signatures. It supports both
/// single-shot signatures (for complete messages in memory) and streaming signatures
/// (for incremental processing of large or streaming data).
///
/// # Design
///
/// This is a zero-sized type that acts as a namespace for signature operations.
/// It delegates to the underlying trait implementations provided by specific
/// signature algorithms (e.g., ECDSA, RSA-PSS, RSA-PKCS1v15).
///
/// # Signature Algorithms
///
/// Different signature algorithms are supported through the type parameter `S`,
/// which must implement either [`SignOp`] for single-shot operations or
/// [`SignStreamingOp`] for streaming operations.
#[derive(Debug)]
pub struct HsmSigner;

impl HsmSigner {
    /// Creates a digital signature over complete data in a single operation.
    ///
    /// This method is suitable for signing complete messages that fit in memory.
    /// It processes the entire data buffer at once and produces the signature.
    ///
    /// # Type Parameters
    ///
    /// * `S` - The signature algorithm implementing [`SignOp`]
    ///
    /// # Arguments
    ///
    /// * `signer` - The signature algorithm instance (may be zero-sized or carry configuration)
    /// * `key` - The private key to use for signing
    /// * `data` - The complete message data to sign
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
    /// - The key is invalid or incompatible with the signature algorithm
    /// - The data length is invalid for the algorithm
    /// - The underlying cryptographic operation fails
    ///
    /// # Performance
    ///
    /// For large messages, consider using [`sign_init`](Self::sign_init) instead
    /// to process data incrementally and reduce memory pressure.
    pub fn sign<Algo: HsmSignOp>(
        signer: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Algo::Error> {
        signer.sign(key, data, signature)
    }

    /// Creates a signature and returns it as a vector.
    ///
    /// This is a convenience method that wraps [`sign`](Self::sign) to handle
    /// buffer allocation automatically. It first queries the required signature
    /// size, allocates a vector, performs the signing, and returns the result.
    ///
    /// # Type Parameters
    ///
    /// * `S` - The signature algorithm implementing [`SignOp`]
    ///
    /// # Arguments
    ///
    /// * `signer` - The signature algorithm instance
    /// * `key` - The private key to use for signing
    /// * `data` - The complete message data to sign
    ///
    /// # Returns
    ///
    /// Returns a vector containing the digital signature.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`sign`](Self::sign).
    ///
    /// # Memory Allocation
    ///
    /// This method allocates a `Vec<u8>` to store the signature. The size is
    /// determined by querying the algorithm implementation. For signature algorithms
    /// like ECDSA or RSA, this is typically 64-512 bytes depending on the key size.
    pub fn sign_vec<Algo: HsmSignOp>(
        signer: &mut Algo,
        key: &Algo::Key,
        data: &[u8],
    ) -> Result<Vec<u8>, Algo::Error> {
        let required_size = signer.sign(key, data, None)?;
        let mut signature = vec![0u8; required_size];
        let written_size = signer.sign(key, data, Some(&mut signature))?;
        signature.truncate(written_size);
        Ok(signature)
    }

    /// Initializes a streaming signature creation context.
    ///
    /// This method creates a context for processing data in multiple chunks,
    /// which is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data sources (network, pipes, iterators)
    /// - Progressive signing with intermediate hashing
    ///
    /// # Type Parameters
    ///
    /// * `S` - The signature algorithm implementing [`SignStreamingOp`]
    ///
    /// # Arguments
    ///
    /// * `signer` - The signature algorithm instance
    /// * `key` - The private key to use for signing
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`SignStreamingOpContext`] that can be
    /// used to process data incrementally via [`update`](SignStreamingOpContext::update)
    /// and finalized with [`finish`](SignStreamingOpContext::finish).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid for this signature algorithm
    /// - The underlying cryptographic provider fails to initialize
    ///
    /// # Thread Safety
    ///
    /// The returned context is not thread-safe and should be used from a single thread.
    pub fn sign_init<S: HsmSignStreamingOp>(
        signer: S,
        key: S::Key,
    ) -> Result<S::Context, S::Error> {
        signer.sign_init(key)
    }
}
