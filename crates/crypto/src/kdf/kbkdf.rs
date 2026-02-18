// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manual KBKDF implementation for platform-independent key derivation.
//!
//! This module provides a pure Rust implementation of KBKDF (Key-Based Key Derivation Function)
//! in Counter Mode as specified in NIST SP 800-108. It serves as a platform-agnostic backend
//! that doesn't depend on OpenSSL or other external cryptographic libraries.
//!
//! # KBKDF Overview
//!
//! KBKDF is a key derivation function that uses a pseudorandom function (PRF) to derive
//! keying material from an existing key. This implementation uses HMAC as the PRF.
//!
//! The derivation follows the pattern:
//! `K(i) = PRF(K_IN, [i]_2 || Label || 0x00 || Context || [L]_2)`
//!
//! Where:
//! - `K(i)` is the output of the i-th iteration
//! - `[i]_2` is the counter (4 bytes, big-endian)
//! - `Label` is optional context-specific label data
//! - `0x00` is a separator byte (when context is present)
//! - `Context` is optional application-specific context data
//! - `[L]_2` is the output length in bits (4 bytes, big-endian, optional)
//!
//! # NIST SP 800-108 Compliance
//!
//! This implementation supports:
//! - Counter location: BEFORE_FIXED (counter precedes fixed input data)
//! - PRF: HMAC with configurable hash algorithms
//! - Optional length field for different NIST test configurations
//! - Configurable label and context parameters
//!
//! # Supported Hash Algorithms
//!
//! - **HMAC-SHA1**: Legacy algorithm (20-byte output)
//! - **HMAC-SHA256**: Recommended for most applications (32-byte output)
//! - **HMAC-SHA384**: High security applications (48-byte output)
//! - **HMAC-SHA512**: Maximum security applications (64-byte output)

use super::*;

/// Manual KBKDF operation provider using HMAC-based PRF.
///
/// This structure configures and executes KBKDF (Key-Based Key Derivation Function)
/// operations in Counter Mode as specified in NIST SP 800-108. It uses HMAC as the
/// pseudorandom function (PRF) and supports configurable fixed input data.
///
/// # Configuration
///
/// - **hash_algo**: The hash algorithm to use for HMAC (SHA-256, SHA-384, etc.)
/// - **label**: Optional application-specific label for context binding (owned)
/// - **context**: Optional additional context data (owned)
/// - **use_len**: Whether to include the output length field in PRF input
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as it only stores owned configuration data.
/// Actual cryptographic operations are performed through HMAC APIs.
///
/// # Security
///
/// - Uses HMAC as the pseudorandom function following NIST SP 800-108
/// - Counter prevents PRF output collisions across iterations
/// - Label and context enable domain separation between different uses
pub struct KbkdfAlgo {
    hash_algo: HashAlgo,
    label: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
    use_len: bool,
}

impl KbkdfAlgo {
    /// Creates a new KBKDF operation provider without length field.
    ///
    /// This constructor configures KBKDF to NOT include the output length field
    /// in the PRF input (use_len = false). This matches many NIST test vectors
    /// and is suitable for scenarios where the length field should be omitted.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash algorithm to use for HMAC-based PRF
    /// * `label` - Optional label for context binding (at least one of label or context required)
    /// * `context` - Optional additional context data
    ///
    /// # Returns
    ///
    /// A new `KbkdfAlgo` instance configured without length field.
    pub fn without_len(hash: HashAlgo, label: Option<Vec<u8>>, context: Option<Vec<u8>>) -> Self {
        Self {
            hash_algo: hash,
            label,
            context,
            use_len: false,
        }
    }
    /// Creates a new KBKDF operation provider with length field.
    ///
    /// This constructor configures KBKDF to include the output length field
    /// in the PRF input (use_len = true). This adds a 4-byte big-endian length
    /// field representing the output length in bits.
    ///
    /// # Arguments
    ///
    /// * `hash` - The hash algorithm to use for HMAC-based PRF
    /// * `label` - Optional label for context binding (at least one of label or context required)
    /// * `context` - Optional additional context data
    ///
    /// # Returns
    ///
    /// A new `KbkdfAlgo` instance configured with length field.
    pub fn with_len(hash: HashAlgo, label: Option<Vec<u8>>, context: Option<Vec<u8>>) -> Self {
        Self {
            hash_algo: hash,
            label,
            context,
            use_len: true,
        }
    }
}

/// Implements KBKDF key derivation operation.
///
/// This implementation uses HMAC-based PRF to derive key material according to
/// NIST SP 800-108 specification in Counter Mode. It performs multiple rounds
/// of PRF computation to generate the requested amount of output key material.
impl DeriveOp for KbkdfAlgo {
    type Key = GenericSecretKey;
    type DerivedKey = GenericSecretKey;

    /// Derives key material using the KBKDF algorithm in Counter Mode.
    ///
    /// This method performs iterative HMAC operations with an incrementing counter
    /// to derive the requested length of key material. Each iteration produces
    /// hash_size bytes of output, which are concatenated to form the final key.
    ///
    /// The number of iterations is calculated as: `⌈derive_len / hash_size⌉`
    ///
    /// # Arguments
    ///
    /// * `key` - Input key material (K_IN) to derive from
    /// * `derive_len` - Desired output length in bytes (must be > 0)
    ///
    /// # Returns
    ///
    /// The derived key material as a `GenericSecretKey` of the requested length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::KbkdfInvalidKdkLength` - Input key is empty (zero length)
    /// - `CryptoError::KbkdfInvalidDerivedKeyLength` - Requested output length is zero
    /// - `CryptoError::KbkdfSetPropertyError` - Both label and context are None
    /// - `CryptoError::KbkdfDeriveError` - HMAC operation fails during derivation
    #[allow(unsafe_code)]
    fn derive(&self, key: &Self::Key, derive_len: usize) -> Result<Self::DerivedKey, CryptoError> {
        // check if key is empty
        if key.size() == 0 {
            Err(CryptoError::KbkdfInvalidKdkLength)?
        }
        //check if derive_len is zero
        if derive_len == 0 {
            Err(CryptoError::KbkdfInvalidDerivedKeyLength)?
        }
        // check if label and context both are not set
        if self.label.is_none() && self.context.is_none() {
            Err(CryptoError::KbkdfSetPropertyError)?
        }

        // calculate number of rounds required
        let rounds = derive_len.div_ceil(self.hash_algo.size());

        // Create a hmac key from base generic secret key
        let hmac_key = HmacKey::try_from(key)?;

        // loop through rounds to derive key
        let mut derived_key = vec![0u8; derive_len];

        for round in 0..rounds {
            // sign input to get hmac output
            let prf = self.compute_prf(&hmac_key, round, derive_len)?;

            // Copy the required bytes to derived key
            let start = round * self.hash_algo.size();
            let len = (derive_len - start).min(self.hash_algo.size());
            let end = start + len;

            derived_key[start..end].copy_from_slice(&prf[..len]);
        }

        // Return the derived key
        GenericSecretKey::from_bytes(&derived_key)
    }
}

impl KbkdfAlgo {
    /// Computes one iteration of the KBKDF PRF using HMAC.
    ///
    /// This function computes a single iteration of the KBKDF Counter Mode formula:
    /// `K(i) = HMAC(K_IN, [i]_2 || Label || 0x00 || Context || [L]_2)`
    ///
    /// # Arguments
    ///
    /// * `hmac_key` - The HMAC key (K_IN) for the PRF
    /// * `counter` - The iteration counter (i), 1-indexed
    /// * `key_size` - The total output length in bytes for the optional length field
    ///
    /// # Returns
    ///
    /// Vector containing the HMAC output (size equals hash algorithm output size).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KbkdfDeriveError` if:
    /// - HMAC initialization fails
    /// - HMAC update operations fail
    /// - HMAC finalization fails
    fn compute_prf(
        &self,
        hmac_key: &HmacKey,
        counter: usize,
        key_size: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        // counter is 1-indexed
        let counter = (counter + 1) as u32;

        //key length is in bits
        let key_size = (key_size * 8) as u32;

        //initialize hmac sign context
        let hmac = HmacAlgo::new(self.hash_algo.clone());
        let mut sign_context =
            Signer::sign_init(hmac, hmac_key.clone()).map_err(|_| CryptoError::KbkdfDeriveError)?;

        // Add counter (4 bytes, big-endian)
        sign_context.update(&counter.to_be_bytes())?;

        // add label if any
        if let Some(label) = &self.label {
            sign_context.update(label.as_ref())?;
        }
        if let Some(context) = &self.context {
            // add separator 0x00
            sign_context.update(&[0x00])?;
            // add context
            sign_context.update(context.as_ref())?;
        }

        if self.use_len {
            //add length in bits (2 bytes, big-endian)
            sign_context.update(&key_size.to_be_bytes())?;
        }

        //finish hmac sign
        let prf = sign_context
            .finish_vec()
            .map_err(|_| CryptoError::KbkdfDeriveError)?;
        Ok(prf)
    }
}
