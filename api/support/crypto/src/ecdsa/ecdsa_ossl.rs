// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! # ECDSA OpenSSL Cryptography Support
//!
//! This module provides ECDSA (Elliptic Curve Digital Signature Algorithm) signing and verification
//! operations using OpenSSL as the cryptographic backend. It supports both one-shot and streaming
//! (multi-part) signing and verification, allowing for flexible integration with various data sources.
//!
//! ## Features
//! - ECDSA signing and verification using OpenSSL's EVP API
//! - Support for multiple elliptic curves and hash algorithms
//! - One-shot and streaming (multi-part) signing and verification contexts
//! - Thread-safe key handle management
//! - Detailed error reporting and tracing
//!
//! ## Usage
//! This module is intended to be used as part of a larger cryptographic library, providing
//! ECDSA functionality for secure message signing and verification.
//!
use openssl::pkey::PKey;
use openssl::pkey_ctx::PkeyCtx;

use super::*;
use crate::eckey::*;
use crate::sha::*;

/// Calculate the maximum DER-encoded ECDSA signature size for a given curve degree.
///
/// # Arguments
/// * `curve_degree` - The curve degree in bits (e.g., 256 for P-256)
///
/// # Returns
/// * Maximum possible DER signature size in bytes
///
/// # Details
/// DER ECDSA signature format: SEQUENCE { INTEGER r, INTEGER s }
/// - SEQUENCE tag (1 byte) + length (1-4 bytes)
/// - For each INTEGER: tag (1 byte) + length (1-4 bytes) + optional leading zero (1 byte) + value
/// - Worst case: both r and s need leading zero bytes for ASN.1 encoding
fn max_der_signature_size(curve_degree: u32) -> usize {
    let key_size = curve_degree.div_ceil(8) as usize;

    // Each integer component (r, s) in worst case:
    // - Tag: 1 byte (0x02)
    // - Length: 1-4 bytes (for key_size <= 127, it's 1 byte; for larger it's 2+ bytes)
    // - Optional leading zero: 1 byte (when high bit is set)
    // - Value: key_size bytes
    let length_bytes = if key_size <= 127 { 1 } else { 2 };
    let max_integer_size = 1 + length_bytes + 1 + key_size; // tag + length + leading_zero + value

    // SEQUENCE overhead:
    // - Tag: 1 byte (0x30)
    // - Length: 1-4 bytes (content length is 2 * max_integer_size)
    let content_length = 2 * max_integer_size;
    let seq_length_bytes = if content_length <= 127 { 1 } else { 2 };

    1 + seq_length_bytes + content_length
}

pub struct EcdsaOsslCryptSignContext {
    hasher: DigestContext,
    hash_algo: HashAlgo,
    private_key: EcPrivateKey,
}

impl EcdsaCryptSignOp for EcPrivateKey {
    /// Signs the given data using the specified hash algorithm (one-shot).
    ///
    /// # Arguments
    /// * `hash_algo` - Hash algorithm to use
    /// * `data` - Message to sign
    /// * `signature` - Output buffer for DER-encoded EC signature
    ///
    /// # Returns
    /// * `Ok(usize)` with signature length on success
    /// * `Err(CryptoError::EccError)` on failure
    fn ecdsa_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let key_guard = self.private_key_handle.lock().unwrap();
        let group = key_guard.ossl_private_key_handle.group();
        let degree = group.degree();
        let curve_id = match EcCurveId::from_bits(degree) {
            Some(val) => val,
            None => {
                tracing::error!(
                    "ecdsa_crypt_sign: unsupported bits for curve (degree: {})",
                    degree,
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!(
                "ecdsa_crypt_sign: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        // Hash the data using the internal sha module
        let mut digest = vec![0u8; hash_algo.hash_length()];
        hash_algo.hash(data, &mut digest)?;
        // Create a PKey from the EC private key
        let pkey = PKey::from_ec_key(key_guard.ossl_private_key_handle.clone()).map_err(|e| {
            tracing::error!(
                "ecdsa_crypt_sign: failed to create PKey from EcKey: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!("ecdsa_crypt_sign: failed to create PkeyCtx: {:?}", e);
            CryptoError::EccError
        })?;
        ctx.sign_init().map_err(|e| {
            tracing::error!("ecdsa_crypt_sign: failed to init sign: {:?}", e);
            CryptoError::EccError
        })?;
        // Use a dynamically sized buffer for DER signature based on curve degree
        let der_buffer_size = max_der_signature_size(degree);
        let mut der_signature = vec![0u8; der_buffer_size];
        let sig_len = ctx.sign(&digest, Some(&mut der_signature)).map_err(|e| {
            tracing::error!("ecdsa_crypt_sign: failed to sign digest: {:?}", e);
            CryptoError::EccError
        })?;
        // convert signature into raw format
        let key_size = degree.div_ceil(8) as usize;

        let signature_raw = der_ecdsa_signature_to_raw(&der_signature[..sig_len], key_size)
            .map_err(|e| {
                tracing::error!(
                    "ecdsa_crypt_sign: failed to convert DER signature to raw: {:?}",
                    e
                );
                CryptoError::EccError
            })?;
        let raw_len = signature_raw.len();
        signature[..raw_len].copy_from_slice(&signature_raw);
        Ok(&signature[..raw_len])
    }

    /// Initializes a streaming signing context for multi-part signing.
    ///
    /// # Arguments
    /// * `algo_handle` - Hash algorithm to use
    ///
    /// # Returns
    /// * `Ok(OsslCryptoSignContext)` on success
    /// * `Err(CryptoError::EccError)` on failure
    fn ecdsa_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl EcdsaCryptSignContextOp, CryptoError> {
        let key_guard = self.private_key_handle.lock().unwrap();
        let group = key_guard.ossl_private_key_handle.group();
        let degree = group.degree();
        let curve_id = match EcCurveId::from_bits(degree) {
            Some(val) => val,
            None => {
                tracing::error!(
                    "ecdsa_crypt_sign: unsupported bits for curve (degree: {})",
                    degree,
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!("ecdsa_crypt_sign_init: unsupported hash algorithm for curve (degree: {}, algo: {:?})", degree, hash_algo);
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let hasher = hash_algo.init().map_err(|e| {
            tracing::error!("ecdsa_crypt_sign: failed to create new hasher: {:?}", e);
            CryptoError::EccError
        })?;
        Ok(EcdsaOsslCryptSignContext {
            hasher,
            hash_algo,
            private_key: self.clone(),
        })
    }

    /// Returns the maximum size in bytes of a DER-encoded ECDSA signature for this key's curve and hash algorithm.
    ///
    /// This value is always at least as large as the largest possible DER-encoded signature for the curve,
    /// and never smaller than any actual signature that could be produced.
    ///
    /// # Arguments
    /// * `hash_algo` - Hash algorithm to check for support with the curve
    ///
    /// # Returns
    /// * `Ok(usize)` with the maximum DER signature size if supported
    /// * `Err(CryptoError::EccUnsupportedHashAlgorithm)` if the hash is not supported for the curve
    /// * `Err(CryptoError::EcCurveMismatch)` for unknown/unsupported curve
    fn ecdsa_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError> {
        let key_guard = self.private_key_handle.lock().unwrap();
        let group = key_guard.ossl_private_key_handle.group();
        let curve_bits = group.degree();
        let curve_id = match EcCurveId::from_bits(curve_bits) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_get_signature_size: unsupported bits for curve (degree: {})",
                    curve_bits
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!(
                "ecdsa_crypt_get_signature_size: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                curve_bits,
                hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        // # Raw ECDSA signature size calculation:
        //
        // The raw ECDSA signature format is simply r || s (concatenated r and s values).
        // For a curve of N bits, each component (r and s) is ceil(N/8) bytes.
        // Total raw signature size = 2 * ceil(curve_bits / 8)
        //
        // For P-256 (256 bits): key_size = 32, raw_sig_size = 64
        // For P-384 (384 bits): key_size = 48, raw_sig_size = 96
        // For P-521 (521 bits): key_size = 66, raw_sig_size = 132
        let key_size = curve_bits.div_ceil(8);
        let raw_sig_size = 2 * key_size as usize;
        Ok(raw_sig_size)
    }
}

impl EcdsaCryptSignContextOp for EcdsaOsslCryptSignContext {
    /// Updates the signing context with more message data.
    ///
    /// # Arguments
    /// * `data` - Message chunk to add
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(CryptoError::EccError)` on failure
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.hasher.update(data)
    }

    /// Finalizes the signature and writes it to the output buffer.
    ///
    /// # Arguments
    /// * `signature` - Output buffer for DER-encoded EC signature
    ///
    /// # Returns
    /// * `Ok(usize)` with signature length on success
    /// * `Err(CryptoError::EccError)` on failure
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError> {
        let mut digest = vec![0u8; self.hash_algo.hash_length()];
        self.hasher.finish(&mut digest)?;
        let key_guard = self.private_key.private_key_handle.lock().unwrap();
        let group = key_guard.ossl_private_key_handle.group();
        let degree = group.degree();
        let pkey = PKey::from_ec_key(key_guard.ossl_private_key_handle.clone()).map_err(|e| {
            tracing::error!(
                "OsslCryptSignContext::finalize: failed to create PKey: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!(
                "OsslCryptSignContext::finalize: failed to create PkeyCtx: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        ctx.sign_init().map_err(|e| {
            tracing::error!(
                "OsslCryptSignContext::finalize: failed to init sign: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        // Use a dynamically sized buffer for DER signature based on curve degree
        let der_buffer_size = max_der_signature_size(degree);
        let mut der_signature = vec![0u8; der_buffer_size];
        let sig_len = ctx.sign(&digest, Some(&mut der_signature)).map_err(|e| {
            tracing::error!(
                "OsslCryptSignContext::finalize: failed to sign digest: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        // convert signature into raw format
        let key_size = degree.div_ceil(8) as usize;
        let signature_raw = der_ecdsa_signature_to_raw(&der_signature[..sig_len], key_size)
            .map_err(|e| {
                tracing::error!(
                    "OsslCryptSignContext::finalize: failed to convert DER signature to raw: {:?}",
                    e
                );
                CryptoError::EccError
            })?;
        let raw_len = signature_raw.len();
        signature[..raw_len].copy_from_slice(&signature_raw);
        Ok(&signature[..raw_len])
    }
}

impl EcdsaCryptVerifyOp for EcPublicKey {
    /// Verifies the given signature for the data (one-shot).
    ///
    /// # Arguments
    /// * `algo_handle` - Hash algorithm to use
    /// * `data` - Message to verify
    /// * `signature` - RAW EC signature
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(CryptoError::EccError)` if invalid or on error
    fn ecdsa_crypt_verify(
        &self,
        algo_handle: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let mut digest = vec![0u8; algo_handle.hash_length()];
        algo_handle.hash(data, &mut digest)?;

        self.ecdsa_crypt_verify_digest(&digest, signature)
    }

    /// Verifies a signature against a pre-computed digest.
    ///
    /// This function performs ECDSA verification on a digest that has already been computed,
    /// rather than computing the hash of the input data. This is useful when you have
    /// already hashed your data or when working with pre-computed test vectors.
    ///
    /// # Arguments
    /// * `digest` - The pre-computed digest/hash that was signed.
    /// * `signature` - The signature to verify against the digest.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if the signature is valid, or an error if verification fails.
    fn ecdsa_crypt_verify_digest(
        &self,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let key_guard = self.public_key_handle.lock().unwrap();
        let pkey = PKey::from_ec_key(key_guard.ossl_public_key_handle.clone()).map_err(|e| {
            tracing::error!(
                "ecdsa_crypt_verify: failed to create PKey from EcKey: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        let group = key_guard.ossl_public_key_handle.group();

        let signature_der =
            raw_ecdsa_signature_to_der(signature, signature.len()).map_err(|e| {
                tracing::error!(
                    "ecdsa_crypt_verify: failed to convert DER signature from raw: {:?}",
                    e
                );
                CryptoError::EccError
            })?;
        // Validate DER signature length after conversion
        if !EcCurveId::is_valid_ec_signature_length(group, signature_der.len()) {
            tracing::error!(
                "ecdsa_crypt_verify: signature length {} out of expected range for curve",
                signature_der.len()
            );
            return Err(CryptoError::EccError);
        }
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!("ecdsa_crypt_verify: failed to create PkeyCtx: {:?}", e);
            CryptoError::EccError
        })?;
        ctx.verify_init().map_err(|e| {
            tracing::error!("ecdsa_crypt_verify: failed to init verify: {:?}", e);
            CryptoError::EccError
        })?;
        match ctx.verify(digest, signature_der.as_slice()) {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::error!("ecdsa_crypt_verify: signature verification failed");
                Err(CryptoError::EccVerifyError)
            }
            Err(e) => {
                tracing::error!(
                    "ecdsa_crypt_verify: failed to finalize verification: {:?}",
                    e
                );
                Err(CryptoError::EccError)
            }
        }
    }

    /// Initializes a streaming verification context for multi-part verification.
    ///
    /// # Arguments
    /// * `algo_handle` - Hash algorithm to use
    ///
    /// # Returns
    /// * `Ok(OsslVerifyContext)` on success
    /// * `Err(CryptoError::EccError)` on failure
    fn ecdsa_crypt_verify_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl EcdsaCryptVerifyContextOp, CryptoError> {
        let hasher = hash_algo.init().map_err(|e| {
            tracing::error!("ecdsa_crypt_verify_init: failed to init hasher: {:?}", e);
            CryptoError::EccError
        })?;
        Ok(EcdsaOsslCryptVerifyContext {
            hasher,
            algo: hash_algo,
            public_key: self.clone(),
        })
    }
}

pub struct EcdsaOsslCryptVerifyContext {
    hasher: DigestContext,
    algo: HashAlgo,
    public_key: EcPublicKey,
}
impl EcdsaCryptVerifyContextOp for EcdsaOsslCryptVerifyContext {
    /// Updates the verification context with more message data.
    ///
    /// # Arguments
    /// * `data` - Message chunk to add
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(CryptoError::EccError)` on failure
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.hasher.update(data)
    }

    /// Finalizes the verification and checks the signature.
    ///
    /// # Arguments
    /// * `signature` - DER-encoded EC signature to verify
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(CryptoError::EccError)` if invalid or on error
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError> {
        let mut digest = vec![0u8; self.algo.hash_length()];
        self.hasher.finish(&mut digest)?;
        let key_guard = self.public_key.public_key_handle.lock().unwrap();
        let pkey = PKey::from_ec_key(key_guard.ossl_public_key_handle.clone()).map_err(|e| {
            tracing::error!(
                "EcCryptVerifyContext::finalize: failed to create PKey: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        let group = key_guard.ossl_public_key_handle.group();
        let signature_der =
            raw_ecdsa_signature_to_der(signature, signature.len()).map_err(|e| {
                tracing::error!(
                "EcCryptVerifyContext::finalize: failed to convert DER signature from raw: {:?}",
                e
            );
                CryptoError::EccError
            })?;
        // Validate raw signature length before conversion
        if !EcCurveId::is_valid_ec_signature_length(group, signature_der.len()) {
            tracing::error!(
                "EcCryptVerifyContext::finalize: signature length {} out of expected range for curve",
                signature_der.len()
            );
            return Err(CryptoError::EccError);
        }
        let mut ctx = PkeyCtx::new(&pkey).map_err(|e| {
            tracing::error!(
                "EcCryptVerifyContext::finalize: failed to create PkeyCtx: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        ctx.verify_init().map_err(|e| {
            tracing::error!(
                "EcCryptVerifyContext::finalize: failed to init verify: {:?}",
                e
            );
            CryptoError::EccError
        })?;
        match ctx.verify(&digest, &signature_der) {
            Ok(true) => Ok(()),
            Ok(false) => {
                tracing::error!("EcCryptVerifyContext::finalize: signature doesn't match");
                Err(CryptoError::EccVerifyError)
            }
            Err(e) => {
                tracing::error!(
                    "ecdsa_crypt_verify: failed to finalize verification: {:?}",
                    e
                );
                Err(CryptoError::EccError)
            }
        }
    }
}
