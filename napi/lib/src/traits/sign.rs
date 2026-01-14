// Copyright (C) Microsoft Corporation. All rights reserved.

use std::error::Error;

use super::*;

/// Trait for single-operation digital signature creation.
///
/// This trait provides a unified interface for creating digital signatures over
/// complete messages in a single operation. It abstracts over different signature
/// schemes (ECDSA, RSA-PSS, RSA-PKCS1v15) and provides a consistent API regardless
/// of the underlying algorithm.
///
/// Implementations handle the complete signature process including any required
/// hashing, padding, and cryptographic transformations in a single atomic operation.
/// This is suitable for scenarios where the entire message fits in memory and can
/// be processed at once.
///
/// # Type Parameters
///
/// * `Key` - The private key type implementing [`HsmKey`]. Different signature
///   algorithms require different key types (ECC keys for ECDSA, RSA keys for
///   RSA-based schemes).
pub trait HsmSignOp {
    /// The private key type used for this signing operation.
    type Key: HsmSigningKey;

    /// The error type returned by this signing operation.
    type Error: Error;

    /// Creates a digital signature over the provided data.
    ///
    /// This method performs the complete signature generation process, which typically
    /// involves hashing the input data (using the algorithm's specified hash function),
    /// applying any required padding schemes, and performing the cryptographic signing
    /// operation using the private key.
    ///
    /// The signature operation is deterministic for some algorithms (e.g., RSA-PKCS1v15)
    /// and non-deterministic for others (e.g., ECDSA, RSA-PSS) depending on whether
    /// random padding or nonces are used.
    ///
    /// # Arguments
    ///
    /// * `key` - The private key to use for signing. Must be compatible with this algorithm.
    /// * `data` - The data to sign. Will be hashed internally if required by the algorithm.
    ///   For hash-based signatures, this is the raw message. The maximum data size depends
    ///   on the algorithm and underlying implementation.
    /// * `signature` - Optional output buffer for the signature. If `None`, only calculates
    ///   the required size without performing the signature operation. If provided, must be
    ///   large enough to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`. Signature sizes are algorithm-dependent:
    /// - ECDSA: Typically 64-132 bytes depending on curve (P-256: 64 bytes, P-521: 132 bytes)
    /// - RSA: Same as key modulus size (e.g., 256 bytes for RSA-2048, 512 bytes for RSA-4096)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small for the output
    /// - The key is invalid or incompatible with this signature algorithm
    /// - The data length exceeds algorithm-specific limits
    /// - The underlying cryptographic operation fails
    /// - Random number generation fails (for probabilistic signatures)
    ///
    /// # Security Considerations
    ///
    /// - Private keys must be kept secure and never exposed
    /// - Signatures should be verified using the corresponding public key
    /// - The same key should not be used across different signature schemes
    /// - For deterministic algorithms, signing the same data twice produces identical signatures
    /// - For probabilistic algorithms, each signature includes fresh randomness
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error>;
}

/// Trait for streaming digital signature creation.
///
/// This trait provides an interface for multi-step signature creation where
/// data is processed incrementally in chunks. The streaming approach maintains
/// an internal hash state across multiple updates, only performing the actual
/// signature operation when finalization is requested.
///
/// This is essential for:
/// - Large files that don't fit in memory (e.g., multi-gigabyte files)
/// - Streaming data sources (network sockets, pipes, iterators)
/// - Progressive signing where data becomes available over time
/// - Memory-constrained environments where buffering is impractical
///
/// The streaming signature process separates the hashing phase (incremental) from
/// the signing phase (atomic at finalization), providing both memory efficiency
/// and consistent security properties with single-shot operations.
///
/// # Type Parameters
///
/// * `Key` - The private key type implementing [`HsmKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`sign_init`](Self::sign_init) to create a context
/// 2. Update: Call [`update`](SignStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](SignStreamingOpContext::finish) to produce the signature
pub trait HsmSignStreamingOp {
    /// The private key type used for this signing operation.
    type Key: HsmSigningKey;

    /// The error type returned by this signing operation.
    type Error: Error;

    /// The context type for streaming signature creation.
    type Context: HsmSignStreamingOpContext<Algo = Self>;

    /// Initializes a streaming signature creation context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context encapsulates the algorithm state, including the hash function
    /// state and the private key reference. The hash state is initialized according
    /// to the signature algorithm's requirements (e.g., SHA-256 for ECDSA-SHA256).
    ///
    /// The returned context maintains internal state across multiple
    /// [`update`](SignStreamingOpContext::update) calls, accumulating the hash
    /// of all processed data until [`finish`](SignStreamingOpContext::finish)
    /// performs the actual signature operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The private key to use for signing. Ownership is typically taken
    ///   to ensure the key remains valid for the context lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`SignStreamingOpContext`] that can be
    /// used to process data incrementally. The context owns or references the
    /// key and hash state.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or incompatible with this signature algorithm
    /// - The key format is corrupted or cannot be parsed
    /// - The underlying cryptographic provider fails to initialize
    /// - Hash function initialization fails
    /// - Required algorithm parameters are missing or invalid
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, Self::Error>;
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
pub trait HsmSignStreamingOpContext {
    /// The signature algorithm type associated with this context.
    type Algo: HsmSignStreamingOp<Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state by feeding the data through the
    /// hash function. The chunks can be of any size and the total data length
    /// is tracked internally.
    ///
    /// No signature operation occurs during update calls - only hash state updates.
    /// The actual signing happens in [`finish`](Self::finish), which finalizes the
    /// hash and performs the cryptographic signature operation.
    ///
    /// Data chunks are processed in the order they are provided, and the final
    /// signature will be over the concatenation of all chunks in sequence.
    ///
    /// # Arguments
    ///
    /// * `data` - Data chunk to process. Can be any size from empty to multiple megabytes.
    ///   Multiple calls with different chunk sizes are supported and produce the same
    ///   result as a single call with concatenated data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The operation has already been finalized
    /// - The underlying hash operation fails
    /// - The internal hash context is in an invalid state
    /// - The total data length exceeds algorithm-specific limits (if any)
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmSignStreamingOp>::Error>;

    /// Finalizes the signature creation operation.
    ///
    /// This method completes the streaming signature process by:
    /// 1. Finalizing the internal hash to produce a digest
    /// 2. Applying any required padding or encoding to the digest
    /// 3. Performing the cryptographic signature operation using the private key
    /// 4. Writing the signature to the output buffer
    ///
    /// The context is consumed by this operation and becomes unusable afterward.
    /// The hash state is finalized and the signature operation completes atomically.
    ///
    /// For probabilistic signatures (ECDSA, RSA-PSS), fresh randomness is generated
    /// during this call. For deterministic signatures, the result depends only on
    /// the key and the data processed via [`update`](Self::update).
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer for the signature. If `None`, only
    ///   calculates and returns the required size without performing the signature
    ///   operation. If provided, must be large enough for the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`. The size is algorithm-dependent:
    /// - ECDSA: Curve-dependent (64 bytes for P-256, 132 bytes for P-521)
    /// - RSA: Key size dependent (256 bytes for RSA-2048, 512 bytes for RSA-4096)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small for the output
    /// - The underlying hash finalization fails
    /// - The signature operation fails
    /// - Random number generation fails (for probabilistic signatures)
    /// - The private key is invalid or inaccessible
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// To create additional signatures, a new context must be initialized via
    /// [`SignStreamingOp::sign_init`]. Attempting to use the context after
    /// finalization results in undefined behavior.
    fn finish(
        &mut self,
        signature: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmSignStreamingOp>::Error>;

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
    fn finish_vec(&mut self) -> Result<Vec<u8>, <Self::Algo as HsmSignStreamingOp>::Error> {
        let required_size = self.finish(None)?;
        let mut signature = vec![0u8; required_size];
        let written_size = self.finish(Some(&mut signature))?;
        signature.truncate(written_size);
        Ok(signature)
    }
}
