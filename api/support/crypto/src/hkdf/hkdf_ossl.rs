// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! HKDF implementation for Linux using the OpenSSL backend.
//!
//! This module provides HKDF (HMAC-based Key Derivation Function) functionality using OpenSSL's
//! HMAC operations to manually implement the Extract-then-Expand approach defined in RFC 5869.
//!
//! The implementation follows the two-phase HKDF algorithm:
//! 1. **Extract Phase**: PRK = HMAC-Hash(salt, IKM) - produces a pseudorandom key
//! 2. **Expand Phase**: OKM = HKDF-Expand(PRK, info, L) - expands PRK to desired length
//!
//! Since the OpenSSL Rust crate doesn't provide direct HKDF functions, this implementation
//! uses OpenSSL's HMAC operations (`PKey::hmac` and `Signer`) to manually construct the
//! HKDF algorithm according to RFC 5869 specification.
//!
//! # Safety
//! This module uses OpenSSL's safe Rust bindings and does not contain unsafe code.

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use super::*;
use crate::secretkey::*;
use crate::sha::HashAlgo;
use crate::CryptoError;

impl HkdfKeyDeriveOps for SecretKey {
    /// Performs HKDF key derivation using OpenSSL's HMAC operations.
    ///
    /// This function implements the complete HKDF algorithm (Extract + Expand phases)
    /// as defined in RFC 5869, using OpenSSL's HMAC operations to manually construct
    /// the key derivation process.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use for HMAC operations.
    /// * `salt` - Optional salt value for the extract phase. If None, a zero-filled salt is used.
    /// * `info` - Optional context and application-specific information for the expand phase.
    /// * `out_len` - The desired length of the derived key material in bytes.
    /// * `secret_key` - Mutable buffer to store the derived key. Must be at least `out_len` bytes.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - A slice of the derived key with length `out_len` on success.
    /// * `Err(CryptoError)` - If the derivation fails due to invalid parameters or backend errors.
    ///
    /// # Errors
    /// * `CryptoError::HkdfOutputBufferTooSmall` - If the output buffer is too small.
    /// * `CryptoError::HkdfExtractFailed` - If the HKDF Extract step fails.
    /// * `CryptoError::HkdfExpandFailed` - If the HKDF Expand step fails.
    /// * `CryptoError::HkdfOutputTooLarge` - If output length exceeds 255 * hash_len.
    /// * `CryptoError::HkdfOutputLengthZero` - If output length is zero.
    /// * `CryptoError::HkdfInvalidPrkLength` - If PRK length is invalid.
    /// * `CryptoError::HkdfHmacKeyFailed` - If HMAC key creation fails.
    /// * `CryptoError::HkdfHmacSignerFailed` - If HMAC signer creation fails.
    ///
    /// # Implementation Details
    /// Manually implements HKDF using OpenSSL's HMAC operations:
    /// 1. Extract phase: PRK = HMAC-Hash(salt, IKM)
    /// 2. Expand phase: OKM = HKDF-Expand(PRK, info, L)
    ///
    /// Both phases are implemented according to RFC 5869 specification.
    fn hkdf_derive<'a>(
        &self,
        hash_algo: HashAlgo,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        out_len: usize,
        secret_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Validate output length is not zero
        if out_len == 0 {
            tracing::error!("Output length cannot be zero");
            return Err(CryptoError::HkdfOutputLengthZero);
        }

        // Validate output buffer size
        if secret_key.len() < out_len {
            tracing::error!(
                "HKDF output buffer too small: required {}, provided {}",
                out_len,
                secret_key.len()
            );
            return Err(CryptoError::HkdfOutputBufferTooSmall);
        }

        // Validate output length doesn't exceed RFC 5869 limits: 255 * HashLen
        let max_output_len = match hash_algo {
            HashAlgo::Sha1 => 255 * 20,   // SHA-1: 20 bytes
            HashAlgo::Sha256 => 255 * 32, // SHA-256: 32 bytes
            HashAlgo::Sha384 => 255 * 48, // SHA-384: 48 bytes
            HashAlgo::Sha512 => 255 * 64, // SHA-512: 64 bytes
        };
        if out_len > max_output_len {
            tracing::error!(
                "Output length {} exceeds RFC 5869 limit of {} for {:?}",
                out_len,
                max_output_len,
                hash_algo
            );
            return Err(CryptoError::HkdfOutputTooLarge);
        }

        // Validate key material is not empty
        if self.kdk.is_empty() {
            tracing::error!("HKDF called with empty input key material");
            return Err(CryptoError::HkdfSecretCreationFailed);
        }

        // Convert HashAlgo to OpenSSL MessageDigest
        let md = match hash_algo {
            HashAlgo::Sha1 => MessageDigest::sha1(),
            HashAlgo::Sha256 => MessageDigest::sha256(),
            HashAlgo::Sha384 => MessageDigest::sha384(),
            HashAlgo::Sha512 => MessageDigest::sha512(),
        };

        // HKDF Extract Phase: PRK = HMAC-Hash(salt, IKM)
        let prk = self.hkdf_extract(md, salt)?;

        // HKDF Expand Phase: OKM = HKDF-Expand(PRK, info, L)
        let okm = self.hkdf_expand(md, &prk, info, out_len)?;

        // Copy derived key to output buffer
        secret_key[..out_len].copy_from_slice(&okm);

        tracing::debug!(
            hash_algo = ?hash_algo,
            salt_len = salt.map(|s| s.len()).unwrap_or(0),
            info_len = info.map(|i| i.len()).unwrap_or(0),
            ikm_len = self.kdk.len(),
            out_len = out_len,
            "HKDF derivation completed successfully"
        );

        Ok(&secret_key[..out_len])
    }
}

impl SecretKey {
    /// HKDF Extract phase: PRK = HMAC-Hash(salt, IKM)
    ///
    /// This function implements the Extract phase of HKDF as defined in RFC 5869.
    /// It computes a pseudorandom key (PRK) from the input key material (IKM) and salt
    /// using HMAC with the specified hash algorithm.
    ///
    /// # Arguments
    /// * `md` - The OpenSSL MessageDigest to use for HMAC operations
    /// * `salt` - Optional salt value. If None, uses a zero-filled salt of hash length
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The pseudorandom key (PRK) on success
    /// * `Err(CryptoError)` - If HMAC operations fail
    ///
    /// # Implementation Details
    /// - Uses salt as HMAC key and IKM as the message to be authenticated
    /// - If no salt is provided, uses zero-filled salt of hash algorithm output length
    /// - Follows RFC 5869 specification: PRK = HMAC-Hash(salt, IKM)
    fn hkdf_extract(&self, md: MessageDigest, salt: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        // Use a salt of hash_len zeros if no salt is provided (RFC 5869)
        let hash_len = md.size();

        // Create HMAC key from salt
        let hmac_key = if let Some(salt_bytes) = salt {
            PKey::hmac(salt_bytes).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    salt_len = salt_bytes.len(),
                    "HKDF Extract: Failed to create HMAC key from provided salt"
                );
                CryptoError::HkdfHmacKeyFailed
            })?
        } else {
            let default_salt = vec![0u8; hash_len];
            PKey::hmac(&default_salt).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    default_salt_len = hash_len,
                    "HKDF Extract: Failed to create HMAC key from default zero salt"
                );
                CryptoError::HkdfHmacKeyFailed
            })?
        };

        // Create signer for HMAC
        let mut signer = Signer::new(md, &hmac_key).map_err(|openssl_error_stack| {
            tracing::error!(
                ?openssl_error_stack,
                hash_len = hash_len,
                "HKDF Extract: Failed to create HMAC signer"
            );
            CryptoError::HkdfHmacSignerFailed
        })?;

        // Sign the input key material (IKM) to produce PRK
        signer.update(&self.kdk).map_err(|openssl_error_stack| {
            tracing::error!(
                ?openssl_error_stack,
                ikm_len = self.kdk.len(),
                "HKDF Extract: Failed to update HMAC with input key material"
            );
            CryptoError::HkdfExtractFailed
        })?;

        let prk = signer.sign_to_vec().map_err(|openssl_error_stack| {
            tracing::error!(
                ?openssl_error_stack,
                "HKDF Extract: Failed to finalize HMAC to produce PRK"
            );
            CryptoError::HkdfExtractFailed
        })?;

        tracing::debug!(
            prk_len = prk.len(),
            expected_len = hash_len,
            "HKDF Extract phase completed successfully"
        );

        Ok(prk)
    }

    /// HKDF Expand phase: OKM = HKDF-Expand(PRK, info, L)
    ///
    /// This function implements the Expand phase of HKDF as defined in RFC 5869.
    /// It expands the pseudorandom key (PRK) into output key material (OKM) of the
    /// desired length using HMAC with the specified hash algorithm.
    ///
    /// # Arguments
    /// * `md` - The OpenSSL MessageDigest to use for HMAC operations
    /// * `prk` - The pseudorandom key from the Extract phase
    /// * `info` - Optional context and application-specific information
    /// * `out_len` - The desired length of output key material in bytes
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The output key material (OKM) of length `out_len` on success
    /// * `Err(CryptoError)` - If HMAC operations fail or output length is invalid
    ///
    /// # Errors
    /// * `CryptoError::HkdfExpandFailed` - If HMAC operations fail during expansion.
    /// * `CryptoError::HkdfOutputTooLarge` - If output length exceeds 255 * hash_len.
    /// * `CryptoError::HkdfOutputLengthZero` - If output length is zero.
    /// * `CryptoError::HkdfInvalidPrkLength` - If PRK length is invalid.
    /// * `CryptoError::HkdfHmacKeyFailed` - If HMAC key creation fails.
    /// * `CryptoError::HkdfHmacSignerFailed` - If HMAC signer creation fails.
    ///
    /// # Implementation Details
    /// - Iteratively computes T(i) = HMAC-Hash(PRK, T(i-1) | info | i) for i = 1 to N
    /// - N = ceil(L / HashLen) where L is the desired output length
    /// - T(0) is empty (not used in first iteration)
    /// - Final OKM is the concatenation of T(1) | T(2) | ... | T(N) truncated to L bytes
    /// - Follows RFC 5869 specification with maximum output length of 255 * HashLen
    fn hkdf_expand(
        &self,
        md: MessageDigest,
        prk: &[u8],
        info: Option<&[u8]>,
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let hash_len = md.size();
        let info_bytes = info.unwrap_or(&[]);

        // Validate PRK length (should be hash_len)
        if prk.len() != hash_len {
            tracing::error!(
                "HKDF Expand: Invalid PRK length: expected {}, got {}",
                hash_len,
                prk.len()
            );
            return Err(CryptoError::HkdfInvalidPrkLength);
        }

        // Validate output length (RFC 5869: must not exceed 255 * hash_len)
        if out_len > 255 * hash_len {
            tracing::error!(
                "HKDF Expand: Output length too large: {} > {} (255 * hash_len)",
                out_len,
                255 * hash_len
            );
            return Err(CryptoError::HkdfOutputTooLarge);
        }

        // Validate non-zero output length
        if out_len == 0 {
            tracing::error!("HKDF Expand: Output length cannot be zero");
            return Err(CryptoError::HkdfOutputLengthZero);
        }

        // Calculate number of iterations needed
        let n = out_len.div_ceil(hash_len);

        tracing::debug!(
            out_len = out_len,
            hash_len = hash_len,
            iterations = n,
            info_len = info_bytes.len(),
            "HKDF Expand: Starting expansion phase"
        );

        let mut okm = Vec::with_capacity(out_len);
        let mut t = Vec::new();

        for i in 1..=n {
            // Create HMAC key from PRK
            let hmac_key = PKey::hmac(prk).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    iteration = i,
                    prk_len = prk.len(),
                    "HKDF Expand: Failed to create HMAC key from PRK for iteration {}",
                    i
                );
                CryptoError::HkdfHmacKeyFailed
            })?;

            // Create signer for HMAC
            let mut signer = Signer::new(md, &hmac_key).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    iteration = i,
                    hash_len = hash_len,
                    "HKDF Expand: Failed to create HMAC signer for iteration {}",
                    i
                );
                CryptoError::HkdfHmacSignerFailed
            })?;

            // T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
            // For i=1, T(0) is empty
            if i > 1 {
                signer.update(&t).map_err(|openssl_error_stack| {
                    tracing::error!(
                        ?openssl_error_stack,
                        iteration = i,
                        t_prev_len = t.len(),
                        "HKDF Expand: Failed to update HMAC with T({}) for iteration {}",
                        i - 1,
                        i
                    );
                    CryptoError::HkdfExpandFailed
                })?;
            }

            signer.update(info_bytes).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    iteration = i,
                    info_len = info_bytes.len(),
                    "HKDF Expand: Failed to update HMAC with info for iteration {}",
                    i
                );
                CryptoError::HkdfExpandFailed
            })?;

            signer.update(&[i as u8]).map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    iteration = i,
                    counter = i as u8,
                    "HKDF Expand: Failed to update HMAC with counter for iteration {}",
                    i
                );
                CryptoError::HkdfExpandFailed
            })?;

            t = signer.sign_to_vec().map_err(|openssl_error_stack| {
                tracing::error!(
                    ?openssl_error_stack,
                    iteration = i,
                    "HKDF Expand: Failed to finalize HMAC for iteration {}",
                    i
                );
                CryptoError::HkdfExpandFailed
            })?;

            // Validate T(i) length
            if t.len() != hash_len {
                tracing::error!(
                    "HKDF Expand: Invalid T({}) length: expected {}, got {}",
                    i,
                    hash_len,
                    t.len()
                );
                return Err(CryptoError::HkdfExpandFailed);
            }

            okm.extend_from_slice(&t);
        }

        // Truncate to desired length
        okm.truncate(out_len);

        tracing::debug!(
            final_okm_len = okm.len(),
            requested_len = out_len,
            iterations_completed = n,
            "HKDF Expand phase completed successfully"
        );

        Ok(okm)
    }
}
