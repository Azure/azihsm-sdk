// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! HMAC implementation for Linux using the OpenSSL backend.
//!
//! This module provides both one-shot and streaming HMAC signing and verification APIs,
//! using the OpenSSL crate for cryptographic operations. It supports all hash algorithms
//! defined in the crate's `sha` module. Errors are captured and logged using the `tracing` crate.
//!
//! Key features:
//! - One-shot and streaming HMAC sign/verify
//! - Secure error handling and tracing
//! - Uses OpenSSL's `Signer` for both signing and verification (see struct-level docs)
//! - Only the OpenSSL crate is used for cryptography
//!
//! # Safety
//! This module may use `unsafe` code where required by the OpenSSL API, but all such usage is
//! carefully contained and justified.

use openssl::pkey::PKey;
use openssl::sign::Signer;

use super::*;
use crate::sha::*;

impl HmacCryptSignOp for HmacKey {
    /// Performs a one-shot HMAC sign operation.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    /// * `data` - The data to sign.
    /// * `signature` - The output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(&[u8])` with the signature on success.
    /// * `Err(CryptoError)` if signing fails.
    fn hmac_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Use self.key directly
        // Check for empty key
        if self.key.is_empty() {
            tracing::error!("HMAC sign called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Check key size bounds using HmacKeyRange
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC sign key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC sign key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        // Check for zero-length signature buffer
        if signature.is_empty() {
            tracing::error!("HMAC sign called with zero-length signature buffer");
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Get the OpenSSL message digest for the requested hash algorithm
        let md = hash_algo.message_digest_from_hash_algo();
        // Create a PKey for HMAC using the provided key
        let pkey = PKey::hmac(self.key.as_slice()).map_err(|e| {
            tracing::error!("openssl PKey::hmac failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Create a Signer context for HMAC
        let mut signer = Signer::new(md, &pkey).map_err(|e| {
            tracing::error!("openssl Signer::new failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Feed the data to the signer
        signer.update(data).map_err(|e| {
            tracing::error!("openssl Signer::update failed: {e}");
            CryptoError::HmacSignFail
        })?;
        // Finalize and get the HMAC result
        let result = signer.sign_to_vec().map_err(|e| {
            tracing::error!("openssl Signer::sign_to_vec failed: {e}");
            CryptoError::HmacSignFail
        })?;
        // Check if the output buffer is large enough
        if signature.len() < result.len() {
            tracing::error!(
                "signature buffer too small: {} < {}",
                signature.len(),
                result.len()
            );
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Copy the result to the output buffer
        signature[..result.len()].copy_from_slice(&result);
        Ok(&signature[..result.len()])
    }

    /// Initializes a streaming signing context for multi-part signing.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(HmacCryptSignContextOp)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    fn hmac_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptSignContextOp, CryptoError> {
        // Use self.key directly
        // Check for empty key
        if self.key.is_empty() {
            tracing::error!("HMAC sign init called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Check key size bounds using HmacKeyRange
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC sign init key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC sign init key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        // Get the OpenSSL message digest for the requested hash algorithm
        let md = hash_algo.message_digest_from_hash_algo();
        // Create a PKey for HMAC using the provided key
        let pkey = PKey::hmac(self.key.as_slice()).map_err(|e| {
            tracing::error!("openssl PKey::hmac failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Create a Signer context for HMAC
        let signer = Signer::new(md, &pkey).map_err(|e| {
            tracing::error!("openssl Signer::new failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Return the streaming context
        Ok(OsslHmacSignContext {
            hmac_signer: signer,
        })
    }

    /// Returns the required signature buffer size for the given hash algorithm.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(usize)` with the required buffer size.
    fn hmac_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError> {
        // Return the output size for the hash algorithm
        Ok(hash_algo.hash_length())
    }
}

/// Streaming HMAC signing context.
struct OsslHmacSignContext {
    hmac_signer: Signer<'static>, // OpenSSL Signer for streaming HMAC
}

impl HmacCryptSignContextOp for OsslHmacSignContext {
    /// Updates the signing context with more data.
    ///
    /// # Arguments
    /// * `data` - The data to add to the HMAC.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails or if data is empty.
    ///
    /// # Note
    /// Empty data is not allowed for streaming HMAC updates. This is to prevent accidental no-op updates and to catch logic errors early.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // Disallow empty updates to catch logic errors
        if data.is_empty() {
            tracing::error!("HMAC update called with empty data slice");
            return Err(CryptoError::HmacSignFail);
        }
        // Feed the data to the signer
        self.hmac_signer.update(data).map_err(|e| {
            tracing::error!("openssl Signer::update failed: {e}");
            CryptoError::HmacSignFail
        })
    }
    /// Finalizes the signature and writes it to the output buffer.
    ///
    /// # Arguments
    /// * `signature` - The output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(&[u8])` with the signature on success.
    /// * `Err(CryptoError)` if finalization fails or the buffer is too small.
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError> {
        // Check for zero-length signature buffer
        if signature.is_empty() {
            tracing::error!("HMAC sign finalize called with zero-length signature buffer");
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Finalize and get the HMAC result
        let sig = self.hmac_signer.sign_to_vec().map_err(|e| {
            tracing::error!("openssl Signer::sign_to_vec failed: {e}");
            CryptoError::HmacSignFail
        })?;
        // Check if the output buffer is large enough
        if signature.len() < sig.len() {
            tracing::error!(
                "signature buffer too small: {} < {}",
                signature.len(),
                sig.len()
            );
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Copy the result to the output buffer
        signature[..sig.len()].copy_from_slice(&sig);
        Ok(&signature[..sig.len()])
    }
}

impl HmacCryptVerifyOp for HmacKey {
    /// Performs a one-shot HMAC verify operation.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    /// * `data` - The data to verify.
    /// * `signature` - The signature to check against.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails or the signature is invalid.
    fn hmac_crypt_verify(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        // Use self.key directly
        // Check for empty key
        if self.key.is_empty() {
            tracing::error!("HMAC verify called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Check key size bounds using HmacKeyRange
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC verify key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC verify key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        // Check for zero-length signature buffer
        if signature.is_empty() {
            tracing::error!("HMAC verify called with zero-length signature buffer");
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Get the OpenSSL message digest for the requested hash algorithm
        let md = hash_algo.message_digest_from_hash_algo();
        // Create a PKey for HMAC using the provided key
        let pkey = PKey::hmac(self.key.as_slice()).map_err(|e| {
            tracing::error!("openssl PKey::hmac failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Create a Signer context for HMAC
        let mut signer = Signer::new(md, &pkey).map_err(|e| {
            tracing::error!("openssl Signer::new failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Feed the data to the signer
        signer.update(data).map_err(|e| {
            tracing::error!("openssl Signer::update failed: {e}");
            CryptoError::HmacVerifyFail
        })?;
        // Finalize and get the HMAC result
        let result = signer.sign_to_vec().map_err(|e| {
            tracing::error!("openssl Signer::sign_to_vec failed: {e}");
            CryptoError::HmacVerifyFail
        })?;
        // Compare the computed HMAC to the provided signature
        if result.as_slice() == signature {
            Ok(())
        } else {
            tracing::error!("HMAC signature mismatch");
            Err(CryptoError::HmacSignatureMismatch)
        }
    }

    /// Initializes a streaming verification context for multi-part verification.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(HmacCryptVerifyContextOp)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    fn hmac_crypt_verify_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptVerifyContextOp, CryptoError> {
        // Use self.key directly
        // Check for empty key
        if self.key.is_empty() {
            tracing::error!("HMAC verify init called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Check key size bounds using HmacKeyRange
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC verify init key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC verify init key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        // Get the OpenSSL message digest for the requested hash algorithm
        let md = hash_algo.message_digest_from_hash_algo();
        // Create a PKey for HMAC using the provided key
        let pkey = PKey::hmac(self.key.as_slice()).map_err(|e| {
            tracing::error!("openssl PKey::hmac failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Create a Signer context for HMAC (used for verification)
        let signer = Signer::new(md, &pkey).map_err(|e| {
            tracing::error!("openssl Signer::new failed: {e}");
            CryptoError::HmacBackendFail
        })?;
        // Return the streaming verification context
        Ok(OsslHmacVerifyContext {
            hmac_signer: signer,
        })
    }
}

/// Streaming HMAC verification context.
struct OsslHmacVerifyContext {
    // Note: We use `Signer` here instead of `Verifier` because OpenSSL's `Verifier` is designed for asymmetric digital signatures (e.g., RSA/ECDSA), not for HMAC.
    // HMAC is a symmetric keyed hash, so verification is performed by recomputing the HMAC over the data and comparing it to the provided signature.
    // The `Signer` API allows us to incrementally update the HMAC state and produce the final tag for comparison.
    // This is the correct and secure approach for HMAC verification in OpenSSL.
    hmac_signer: Signer<'static>,
}

/// Streaming HMAC verification operations.
impl HmacCryptVerifyContextOp for OsslHmacVerifyContext {
    /// Updates the verification context with more data.
    ///
    /// # Arguments
    /// * `data` - The data to add to the HMAC verification.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails or if data is empty.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // Disallow empty updates to catch logic errors
        if data.is_empty() {
            tracing::error!("HMAC verify update called with empty data slice");
            return Err(CryptoError::HmacVerifyFail);
        }
        // Feed the data to the signer
        self.hmac_signer.update(data).map_err(|e| {
            tracing::error!("openssl Signer::update failed: {e}");
            CryptoError::HmacVerifyFail
        })
    }
    /// Finalizes the verification and checks the signature.
    ///
    /// # Arguments
    /// * `signature` - The signature to check against.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails or the signature is invalid.
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError> {
        // Check for zero-length signature buffer
        if signature.is_empty() {
            tracing::error!("HMAC verify finalize called with zero-length signature buffer");
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Finalize and get the HMAC result
        let result = self.hmac_signer.sign_to_vec().map_err(|e| {
            tracing::error!("openssl Signer::sign_to_vec failed: {e}");
            CryptoError::HmacVerifyFail
        })?;
        // Compare the computed HMAC to the provided signature
        if result.as_slice() == signature {
            Ok(())
        } else {
            tracing::error!("HMAC signature mismatch");
            Err(CryptoError::HmacSignatureMismatch)
        }
    }
}
