// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto::HashOpContext;
use azihsm_crypto::{self as crypto};

use super::*;

/// ECC digital signature algorithm implementation using raw elliptic curve operations.
///
/// This type provides HSM-backed ECC signature and verification operations supporting
/// various elliptic curves (P-256, P-384, P-521). Unlike full ECDSA implementations,
/// this operates on pre-computed hashes provided by the caller, allowing flexible
/// hash algorithm selection and support for custom message preparation.
///
/// The caller is responsible for:
/// - Hashing the message data using an appropriate hash algorithm
/// - Ensuring the hash size matches the curve requirements
/// - Managing any required padding or message encoding
///
/// ECC signatures provide:
/// - Strong security with smaller key sizes compared to RSA
/// - Probabilistic signatures (each signature includes fresh randomness)
/// - Non-deterministic behavior unless using RFC 6979 deterministic ECDSA
///
/// # Supported Operations
///
/// - [`SignOp`]: Single-shot signature generation over pre-computed hash
/// - [`SignStreamingOp`]: Streaming signature generation for incremental hash computation
/// - [`VerifyOp`]: Single-shot signature verification over pre-computed hash
/// - [`VerifyStreamingOp`]: Streaming signature verification for incremental hash computation
///
/// # Implementation Notes
///
/// The algorithm delegates to the HSM's underlying cryptographic provider, which may
/// be hardware-accelerated. Key material never leaves the HSM's secure boundary.
pub struct HsmHashSignAlgo {
    hash_algo: HsmHashAlgo,
}

impl HsmHashSignAlgo {
    /// Creates a new `HsmHashSignAlgo` instance for the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_algo` - The hash algorithm to use (e.g., SHA-256, SHA-384, SHA-512)
    ///
    /// # Returns
    ///
    /// A new instance of `HsmEcdsaHashAlgo` configured for the specified hash algorithm.
    pub fn new(hash_algo: HsmHashAlgo) -> Self {
        Self { hash_algo }
    }
}

impl HsmSignOp for HsmHashSignAlgo {
    type Key = HsmEccPrivateKey;
    type Error = HsmError;

    /// Creates an ECC signature over the provided hash in a single operation.
    ///
    /// This method performs raw elliptic curve signature generation on a pre-computed hash:
    /// 1. Accepts the message hash computed by the caller
    /// 2. Generates a cryptographically secure random ephemeral key (k)
    /// 3. Computes the signature components (r, s) using elliptic curve operations
    /// 4. Encodes the signature in the appropriate format
    ///
    /// The signature generation is probabilistic - signing the same hash twice will
    /// produce different (but equally valid) signatures due to the random k value.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC private key to use for signing. Must be compatible with the
    ///   configured elliptic curve (e.g., P-256, P-384, P-521).
    /// * `data` - The pre-computed message hash. The caller is responsible for hashing
    ///   the original message. Hash size should match curve requirements (e.g., 32 bytes
    ///   for P-256, 48 bytes for P-384, 64+ bytes for P-521).
    /// * `signature` - Optional output buffer. If `None`, returns the required signature
    ///   size. If provided, must be large enough to hold the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`. Typical sizes:
    /// - P-256: 64 bytes (raw) or ~70-72 bytes (DER)
    /// - P-384: 96 bytes (raw) or ~102-104 bytes (DER)
    /// - P-521: 132 bytes (raw) or ~137-139 bytes (DER)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The key is invalid or incompatible with the configured curve
    /// - The hash length is invalid for the configured curve
    /// - Random number generation fails
    /// - The HSM signature operation fails
    fn sign(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        let hash = crypto::Hasher::hash_vec(&mut crypto::HashAlgo::from(self.hash_algo), data)
            .map_err(|_| HsmError::InternalError)?;
        let mut algo = HsmEccSignAlgo::default();
        HsmSigner::sign(&mut algo, key, &hash, signature)
    }
}

impl HsmSignStreamingOp for HsmHashSignAlgo {
    // The ECC private key used for signing operations.
    type Key = HsmEccPrivateKey;

    // The error type for ECC signing operations.
    type Error = HsmError;

    // The context type for streaming ECC signature creation.
    type Context = HsmEccSignContext;

    /// Initializes a streaming ECC signature creation context.
    ///
    /// Creates a context that can accumulate hash data incrementally before generating
    /// the final signature. The caller is responsible for feeding hash chunks. The context
    /// maintains:
    /// - The accumulated hash state for incremental processing
    /// - Reference to the private key for the signing operation
    /// - Algorithm configuration (curve type, encoding format)
    ///
    /// The actual signature generation (including random k generation and elliptic
    /// curve operations) is deferred until [`SignStreamingOpContext::finish`] is called.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC private key to use for signing. Ownership is taken to ensure
    ///   the key remains valid for the context's lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context that implements [`SignStreamingOpContext`], ready to process
    /// hash data via [`update`](SignStreamingOpContext::update) calls.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or incompatible with the configured curve
    /// - The key format is corrupted or cannot be parsed
    /// - The HSM fails to initialize the signing context
    /// - Required algorithm parameters are missing or invalid
    fn sign_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        let hasher = crypto::Hasher::hash_init(crypto::HashAlgo::from(self.hash_algo))
            .map_hsm_err(HsmError::InternalError)?;
        Ok(HsmEccSignContext {
            algo: HsmEccSignAlgo::default(),
            hasher,
            key,
        })
    }
}

/// Context for streaming ECC signature creation.
///
/// This context manages the state for computing ECC signatures over hash data that
/// arrives incrementally. The caller is responsible for computing the message hash
/// and feeding it to this context, which accumulates the hash state before performing
/// the final elliptic curve signature operation.
///
/// # Internal State
///
/// The context encapsulates:
/// - Accumulated hash state: Collects hash chunks processed via [`update`](SignStreamingOpContext::update)
/// - Private key reference: Used for the final signature operation
/// - Algorithm configuration: Curve type, encoding format
///
/// # Lifecycle
///
/// 1. Created via [`SignStreamingOp::sign_init`]
/// 2. Hash data processed incrementally via [`update`](SignStreamingOpContext::update)
/// 3. Signature generated and context consumed via [`finish`](SignStreamingOpContext::finish)
///
/// # Memory Efficiency
///
/// The streaming approach maintains only the accumulated hash state, making it suitable
/// for scenarios where the hash is computed externally or arrives in chunks.
///
/// # Thread Safety
///
/// This context is not thread-safe. Each context should be used from a single thread.
/// For concurrent signing operations, create separate contexts.
pub struct HsmEccSignContext {
    algo: HsmEccSignAlgo,
    key: HsmEccPrivateKey,
    hasher: crypto::HashAlgoContext,
}

impl HsmSignStreamingOpContext for HsmEccSignContext {
    type Algo = HsmHashSignAlgo;

    /// Processes a chunk of hash data for ECC signature generation.
    ///
    /// This method accumulates hash chunks incrementally. No signature computation
    /// occurs during update - only hash state accumulation. Multiple calls collect
    /// all hash data in the order provided.
    ///
    /// The caller is responsible for computing the message hash and feeding it through
    /// this method. The accumulated hash will be used as input to the ECC signature
    /// algorithm when [`finish`](Self::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `data` - Hash data chunk to process. The caller should provide the message hash
    ///   computed using an appropriate hash algorithm. Can be provided in chunks or all at once.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context has already been finalized
    /// - The hash accumulation operation fails
    /// - The internal context state is corrupted
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmSignStreamingOp>::Error> {
        self.hasher
            .update(data)
            .map_err(|_| HsmError::InternalError)
    }

    /// Finalizes the streaming ECC signature generation.
    ///
    /// This method completes the signature process by:
    /// 1. Using the accumulated hash data provided by the caller
    /// 2. Generating a cryptographically secure random ephemeral key (k)
    /// 3. Computing the ECC signature components (r, s) via elliptic curve operations
    /// 4. Encoding the signature in the appropriate format
    ///
    /// The context is consumed and becomes unusable after this call.
    ///
    /// # Arguments
    ///
    /// * `signature` - Optional output buffer. If `None`, returns the required signature
    ///   size without performing the signature operation. If provided, must be large
    ///   enough for the signature.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the signature buffer, or the required
    /// buffer size if `signature` is `None`. Size depends on the curve:
    /// - P-256: 64 bytes (raw) or ~70-72 bytes (DER)
    /// - P-384: 96 bytes (raw) or ~102-104 bytes (DER)
    /// - P-521: 132 bytes (raw) or ~137-139 bytes (DER)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature buffer is too small
    /// - The accumulated hash length is invalid for the configured curve
    /// - Random number generation fails
    /// - The elliptic curve signature operation fails
    /// - The private key is invalid or inaccessible
    fn finish(
        &mut self,
        signature: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmSignStreamingOp>::Error> {
        let Some(curve) = self.key.ecc_curve() else {
            return Err(HsmError::InvalidKey);
        };

        let expected_len = curve.signature_size();
        let Some(signature) = signature else {
            return Ok(expected_len);
        };

        let hash = self
            .hasher
            .finish_vec()
            .map_hsm_err(HsmError::InternalError)?;
        HsmSigner::sign(&mut self.algo, &self.key, &hash, Some(signature))
    }
}

impl HsmVerifyOp for HsmHashSignAlgo {
    type Key = HsmEccPublicKey;
    type Error = HsmError;

    /// Verifies an ECC signature over the provided hash in a single operation.
    ///
    /// This method performs raw elliptic curve signature verification on a pre-computed hash:
    /// 1. Accepts the message hash computed by the caller
    /// 2. Decodes the signature to extract the (r, s) components
    /// 3. Performs elliptic curve operations to verify the signature
    /// 4. Returns whether the signature is valid
    ///
    /// The verification uses the public key to check that the signature was created
    /// by the corresponding private key. This is a constant-time operation to prevent
    /// timing attacks where possible.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC public key to use for verification. Must correspond to the
    ///   private key used for signing and match the configured curve.
    /// * `data` - The pre-computed message hash. Must be identical to the hash used
    ///   during signing. The caller is responsible for hashing the original message.
    /// * `signature` - The signature to verify. Expected format depends on the
    ///   implementation (raw concatenated r,s or DER-encoded).
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature is valid for the given hash and public key
    /// - `Ok(false)` - The signature is invalid (wrong key, modified hash, or incorrect signature)
    /// - `Err` - The verification operation itself failed (malformed input, system error)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key format is invalid or corrupted
    /// - The key is incompatible with the configured curve
    /// - The signature format is malformed or has incorrect length
    /// - The hash length is invalid for the configured curve
    /// - The HSM verification operation fails
    fn verify(
        &mut self,
        key: &Self::Key,
        data: &[u8],
        signature: &[u8],
    ) -> Result<bool, Self::Error> {
        let hash = crypto::Hasher::hash_vec(&mut crypto::HashAlgo::from(self.hash_algo), data)
            .map_err(|_| HsmError::InternalError)?;
        let mut algo = HsmEccSignAlgo::default();
        HsmVerifier::verify(&mut algo, key, &hash, signature)
    }
}

impl HsmVerifyStreamingOp for HsmHashSignAlgo {
    type Key = HsmEccPublicKey;
    type Error = HsmError;
    type Context = HsmEccVerifyContext;

    /// Initializes a streaming ECC signature verification context.
    ///
    /// Creates a context that can accumulate hash data incrementally before verifying
    /// the signature. The caller is responsible for feeding hash chunks. The context
    /// maintains:
    /// - The accumulated hash state for incremental processing
    /// - Reference to the public key for the verification operation
    /// - Algorithm configuration (curve type, encoding format)
    ///
    /// The actual signature verification (elliptic curve operations) is deferred until
    /// [`VerifyStreamingOpContext::finish`] is called with the signature.
    ///
    /// # Arguments
    ///
    /// * `key` - The ECC public key to use for verification. Ownership is taken to
    ///   ensure the key remains valid for the context's lifetime.
    ///
    /// # Returns
    ///
    /// Returns a context that implements [`VerifyStreamingOpContext`], ready to process
    /// hash data via [`update`](VerifyStreamingOpContext::update) calls.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is invalid or incompatible with the configured curve
    /// - The key format is corrupted or cannot be parsed
    /// - The public key point is not on the curve
    /// - The HSM fails to initialize the verification context
    /// - Required algorithm parameters are missing or invalid
    fn verify_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        let hasher = crypto::Hasher::hash_init(crypto::HashAlgo::from(self.hash_algo))
            .map_hsm_err(HsmError::InternalError)?;
        Ok(HsmEccVerifyContext {
            algo: HsmEccSignAlgo::default(),
            hasher,
            key,
        })
    }
}

/// Context for streaming ECC signature verification.
///
/// This context manages the state for verifying ECC signatures over hash data that
/// arrives incrementally. The caller is responsible for computing the message hash
/// and feeding it to this context, which accumulates the hash state before performing
/// the final elliptic curve verification operation.
///
/// # Internal State
///
/// The context encapsulates:
/// - Accumulated hash state: Collects hash chunks processed via [`update`](VerifyStreamingOpContext::update)
/// - Public key reference: Used for the final verification operation
/// - Algorithm configuration: Curve type, signature format
///
/// # Lifecycle
///
/// 1. Created via [`VerifyStreamingOp::verify_init`]
/// 2. Hash data processed incrementally via [`update`](VerifyStreamingOpContext::update)
/// 3. Signature verified and context consumed via [`finish`](VerifyStreamingOpContext::finish)
///
/// # Memory Efficiency
///
/// The streaming approach maintains only the accumulated hash state, making it suitable
/// for scenarios where the hash is computed externally or arrives in chunks.
///
/// # Thread Safety
///
/// This context is not thread-safe. Each context should be used from a single thread.
/// For concurrent verification operations, create separate contexts.
pub struct HsmEccVerifyContext {
    algo: HsmEccSignAlgo,
    key: HsmEccPublicKey,
    hasher: crypto::HashAlgoContext,
}

impl HsmVerifyStreamingOpContext for HsmEccVerifyContext {
    type Algo = HsmHashSignAlgo;

    /// Processes a chunk of hash data for ECC signature verification.
    ///
    /// This method accumulates hash chunks incrementally. No verification occurs
    /// during update - only hash state accumulation. Multiple calls collect all
    /// hash data in the order provided.
    ///
    /// The caller is responsible for computing the message hash and feeding it through
    /// this method. The accumulated hash will be verified against the signature when
    /// [`finish`](Self::finish) is called.
    ///
    /// # Arguments
    ///
    /// * `data` - Hash data chunk to process. The caller should provide the message hash
    ///   computed using the same hash algorithm that was used during signing. Can be
    ///   provided in chunks or all at once.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The context has already been finalized
    /// - The hash accumulation operation fails
    /// - The internal context state is corrupted
    fn update(&mut self, data: &[u8]) -> Result<(), <Self::Algo as HsmVerifyStreamingOp>::Error> {
        self.hasher
            .update(data)
            .map_hsm_err(HsmError::InternalError)
    }

    /// Finalizes the streaming ECC signature verification.
    ///
    /// This method completes the verification process by:
    /// 1. Using the accumulated hash data provided by the caller
    /// 2. Decoding the signature to extract the (r, s) components
    /// 3. Performing elliptic curve operations to verify the signature
    /// 4. Comparing the computed and provided values
    ///
    /// The context is consumed and becomes unusable after this call. Verification
    /// is constant-time where possible to prevent timing attacks.
    ///
    /// # Arguments
    ///
    /// * `signature` - The signature to verify. Expected format depends on the
    ///   implementation (raw concatenated r,s or DER-encoded). Size should match
    ///   the curve (64 bytes for P-256, 96 for P-384, 132 for P-521 in raw format).
    ///
    /// # Returns
    ///
    /// Returns a three-state result:
    /// - `Ok(true)` - The signature is valid for the processed hash and public key
    /// - `Ok(false)` - The signature is invalid (wrong key, modified hash, or incorrect signature)
    /// - `Err` - The verification operation itself failed (malformed input, system error)
    ///
    /// Note that `Ok(false)` is not an error - it indicates the signature doesn't match,
    /// which is expected for tampered data or incorrect keys.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature format is malformed or has incorrect length
    /// - The accumulated hash length is invalid for the configured curve
    /// - The elliptic curve verification operation fails
    /// - The public key is invalid or inaccessible
    /// - Required algorithm parameters are missing
    fn finish(
        &mut self,
        signature: &[u8],
    ) -> Result<bool, <Self::Algo as HsmVerifyStreamingOp>::Error> {
        let hash = self
            .hasher
            .finish_vec()
            .map_hsm_err(HsmError::InternalError)?;
        HsmVerifier::verify(&mut self.algo, &self.key, &hash, signature)
    }
}
