// Copyright (C) Microsoft Corporation. All rights reserved.

use std::error::Error;

use super::*;

/// Trait for single-operation digital signature verification.
///
/// This trait provides a unified interface for verifying digital signatures over
/// complete messages in a single operation. It abstracts over different signature
/// schemes (ECDSA, RSA-PSS, RSA-PKCS1v15) and provides a consistent API regardless
/// of the underlying algorithm.
///
/// Implementations handle the complete verification process including hashing the
/// message, applying algorithm-specific transformations, and verifying the signature
/// matches using the public key. All operations occur atomically in a single call.
///
/// The verification result clearly distinguishes between invalid signatures (returns
/// `Ok(false)`) and verification failures due to errors (returns `Err`).
///
/// # Type Parameters
///
/// * `Key` - The public key type implementing [`HsmKey`]. Different signature
///   algorithms require different key types (ECC keys for ECDSA, RSA keys for
///   RSA-based schemes).
pub trait HsmVerifyOp {
    /// The public key type used for this verification operation.
    type Key: HsmVerificationKey;

    /// The error type returned by this verification operation.
    type Error: Error;

    /// Verifies a digital signature over the provided data.
    ///
    /// This method performs the complete verification process, which typically involves:
    /// 1. Hashing the input data using the algorithm's specified hash function
    /// 2. Decoding and validating the signature format
    /// 3. Applying algorithm-specific verification logic using the public key
    /// 4. Comparing the computed and provided values to determine validity
    ///
    /// The verification is constant-time where possible to prevent timing attacks,
    /// though this depends on the underlying cryptographic implementation.
    ///
    /// # Arguments
    ///
    /// * `key` - The public key to use for verification. Must correspond to the private
    ///   key used for signing and be compatible with this signature algorithm.
    /// * `data` - The data that was signed. Must be identical to the data provided during
    ///   signing. Will be hashed internally if required by the algorithm. For hash-based
    ///   signatures, this is the raw message.
    /// * `signature` - The signature to verify. Must match the algorithm's signature format
    ///   and encoding. Size depends on the algorithm (64-132 bytes for ECDSA, key-size
    ///   dependent for RSA).
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature is cryptographically valid for the given data and key
    /// - `Ok(false)` - The signature is invalid (wrong key, modified data, or incorrect signature)
    /// - `Err` - The verification operation itself failed (malformed input, system error)
    ///
    /// Note that `Ok(false)` is not an error condition - it simply means the signature
    /// doesn't match, which is expected for tampered data or incorrect keys.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key format is invalid or corrupted
    /// - The key is incompatible with this signature algorithm
    /// - The data length exceeds algorithm-specific limits
    /// - The signature format is malformed or has incorrect length
    /// - The underlying cryptographic operation fails
    /// - Required algorithm parameters are missing
    ///
    /// # Security Considerations
    ///
    /// - Public keys can be freely distributed and don't require protection
    /// - A valid signature proves the signer possessed the corresponding private key
    /// - Signature validity does not imply trust in the signer's identity
    /// - The same data with different signatures should verify independently
    /// - Failed verifications should not leak information about why they failed
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error>;
}

/// Trait for streaming digital signature verification.
///
/// This trait provides an interface for multi-step signature verification where
/// data is processed incrementally in chunks. The streaming approach maintains
/// an internal hash state across multiple updates, only performing the actual
/// verification operation when finalization is requested.
///
/// This is essential for:
/// - Large files that don't fit in memory (e.g., multi-gigabyte files)
/// - Streaming data sources (network sockets, pipes, iterators)
/// - Progressive verification where data becomes available over time
/// - Memory-constrained environments where buffering is impractical
///
/// The streaming verification process separates the hashing phase (incremental)
/// from the verification phase (atomic at finalization), providing both memory
/// efficiency and consistent security properties with single-shot operations.
///
/// # Type Parameters
///
/// * `Key` - The public key type implementing [`HsmKey`]
///
/// # Lifecycle
///
/// 1. Initialize: Call [`verify_init`](Self::verify_init) to create a context
/// 2. Update: Call [`update`](HsmVerifyStreamingOpContext::update) repeatedly with data chunks
/// 3. Finalize: Call [`finish`](HsmVerifyStreamingOpContext::finish) to verify the signature
pub trait HsmVerifyStreamingOp {
    /// The public key type used for this verification operation.
    type Key: HsmVerificationKey;

    /// The error type returned by this verification operation.
    type Error: Error;

    /// The context type for streaming signature verification.
    type Context: HsmVerifyStreamingOpContext<Algo = Self>;

    /// Initializes a streaming signature verification context.
    ///
    /// This method creates a new context for processing data in multiple chunks.
    /// The context encapsulates the algorithm state, including the hash function
    /// state and the public key reference. The hash state is initialized according
    /// to the signature algorithm's requirements (e.g., SHA-256 for ECDSA-SHA256).
    ///
    /// The returned context maintains internal state across multiple
    /// [`update`](VerifyStreamingOpContext::update) calls, accumulating the hash
    /// of all processed data until [`finish`](VerifyStreamingOpContext::finish)
    /// performs the actual verification operation.
    ///
    /// # Arguments
    ///
    /// * `key` - The public key to use for verification. Ownership is typically taken
    ///   to ensure the key remains valid for the context lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context implementing [`VerifyStreamingOpContext`] that can be
    /// used to process data incrementally. The context owns or references the
    /// key and hash state.
    ///
    // # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or incompatible with this signature algorithm
    /// - The key format is corrupted or cannot be parsed
    /// - The underlying cryptographic provider fails to initialize
    /// - Hash function initialization fails
    /// - Required algorithm parameters are missing or invalid
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, Self::Error>;
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
pub trait HsmVerifyStreamingOpContext {
    /// The verification algorithm type associated with this context.
    type Algo: HsmVerifyStreamingOp<Context = Self>;

    /// Processes a chunk of data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// Each call updates the internal hash state by feeding the data through the
    /// hash function. The chunks can be of any size and the total data length
    /// is tracked internally.
    ///
    /// No verification operation occurs during update calls - only hash state updates.
    /// The actual verification happens in [`finish`](Self::finish), which finalizes
    /// the hash and performs the cryptographic verification operation.
    ///
    /// Data chunks must be processed in the same order they were signed to produce
    /// a valid verification. The final hash will be over the concatenation of all
    /// chunks in sequence.
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
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmVerifyStreamingOp>::Error>;

    /// Finalizes the signature verification operation.
    ///
    /// This method completes the streaming verification process by:
    /// 1. Finalizing the internal hash to produce a digest
    /// 2. Decoding and validating the signature format
    /// 3. Applying algorithm-specific verification logic using the public key
    /// 4. Comparing the computed digest with the signature value
    ///
    /// The context is consumed by this operation and becomes unusable afterward.
    /// The hash state is finalized and the verification operation completes atomically.
    ///
    /// The verification is constant-time where possible to prevent timing attacks,
    /// though this depends on the underlying cryptographic implementation.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify. Must match the algorithm's signature
    ///   format and encoding. Size depends on the algorithm (64-132 bytes for ECDSA,
    ///   key-size dependent for RSA).
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature is cryptographically valid for the processed data and key
    /// - `Ok(false)` - The signature is invalid (wrong key, modified data, or incorrect signature)
    /// - `Err` - The verification operation itself failed (malformed input, system error)
    ///
    /// Note that `Ok(false)` is not an error condition - it simply means the signature
    /// doesn't match the data processed through [`update`](Self::update), which is
    /// expected for tampered data or incorrect keys.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature format is malformed or has incorrect length
    /// - The underlying hash finalization fails
    /// - The verification operation fails
    /// - The public key is invalid or inaccessible
    /// - Required algorithm parameters are missing
    ///
    /// # Note
    ///
    /// After calling this method, the context is consumed and cannot be reused.
    /// To perform additional verifications, a new context must be initialized via
    /// [`VerifyStreamingOp::verify_init`]. Attempting to use the context after
    /// finalization results in undefined behavior.
    fn finish(
        &mut self,
        signature: &[u8],
    ) -> Result<bool, <Self::Algo as HsmVerifyStreamingOp>::Error>;
}
