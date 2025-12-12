// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! # ECDSA Cryptography using Windows CNG
//!
//! This module provides ECDSA (Elliptic Curve Digital Signature Algorithm) signing and verification
//! functionality using the Windows Cryptography Next Generation (CNG) API. It offers both one-shot and
//! streaming interfaces for signing and verifying data with elliptic curve keys, supporting multiple
//! hash algorithms as permitted by the curve and platform.
//!
//! ## Features
//! - ECDSA signing and verification using Windows CNG primitives
//! - Support for multiple elliptic curves and hash algorithms
//! - Thread-safe key handle management using `Arc<Mutex<...>>`
//! - Streaming (incremental) and one-shot signing/verifying APIs
//! - Automatic conversion between raw and DER-encoded ECDSA signatures
//! - Detailed error handling and tracing for debugging and diagnostics
//!
//! ## Safety
//! This crate makes use of unsafe code to interface with the Windows CNG API. All unsafe blocks are
//! carefully documented and reviewed to ensure pointer and handle validity.
//!
//! ## Usage
//! This module is intended for use within the context of the larger cryptographic library and is not
//! meant to be used directly. Please refer to the higher-level APIs for typical usage patterns.
//!
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::eckey::*;
use crate::sha::*;

// Streaming context for sign
struct CngSignContext {
    digest_ctx: DigestContext,
    private_key: EcPrivateKey, // Use EcPrivateKey directly, no extra Arc/Mutex needed
    hash_algo: HashAlgo,
}

// Streaming context for verify
struct CngVerifyContext {
    digest_ctx: DigestContext,
    public_key: EcPublicKey, // Use EcPublicKey directly, no extra Arc/Mutex needed
    hash_algo: HashAlgo,
}

impl EcdsaCryptSignOp for EcPrivateKey {
    /// Signs the given data using the specified hash algorithm and writes the signature.
    ///
    /// # Arguments
    /// * `algo_handle` - The hash algorithm to use (HashAlgo).
    /// * `data` - The data to sign.
    /// * `signature` - The buffer to write the signature to.
    ///
    /// # Returns
    /// * `Result<usize, CryptoError>` - The size of the signature, or an error if signing fails.
    #[allow(unsafe_code)]
    fn ecdsa_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        let degree = self.private_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_sign: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!(
                "ecdsa_crypt_sign: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let hash_len = hash_algo.hash_length();
        let mut hash = vec![0u8; hash_len];
        hash_algo.hash(data, &mut hash)?;
        let mut sig_len: u32 = 0;
        // SAFETY: Calls BCryptSignHash to determine the required signature buffer size; all pointers and handles are valid and checked.
        let status = unsafe {
            BCryptSignHash(
                self.private_key_handle.lock().unwrap().cng_private_key,
                None,
                hash.as_mut_slice(),
                None,
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (size query) failed: status={:?}", status);
            return Err(CryptoError::EccError);
        }
        if signature.len() < sig_len as usize {
            tracing::error!("ecdsa_crypt_sign: signature buffer too small");
            return Err(CryptoError::EccError);
        }
        let mut sig_vec = vec![0; sig_len as usize];
        //SAFETY: Call hash function
        let status = unsafe {
            BCryptSignHash(
                self.private_key_handle.lock().unwrap().cng_private_key,
                None,
                hash.as_mut_slice(),
                Some(sig_vec.as_mut_slice()),
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };

        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (sign) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        // Debug: Print raw signature and expected length
        let curve_bits = self.private_key_handle.lock().unwrap().curve_degree()?;
        let key_size = curve_bits.div_ceil(8) as usize;
        tracing::debug!(
            "CNG raw signature (hex): {:02x?}, sig_len: {}, expected: {}",
            sig_vec,
            sig_len,
            2 * key_size
        );

        // If sig_len is less than expected, left-pad with zeros
        if sig_len as usize != 2 * key_size {
            tracing::warn!(
                "CNG raw signature length {} does not match expected {}. Padding with zeros.",
                sig_len,
                2 * key_size
            );
            let mut padded = vec![0u8; 2 * key_size];
            if sig_len as usize > 0 && sig_len as usize <= 2 * key_size {
                padded[2 * key_size - sig_len as usize..]
                    .copy_from_slice(&sig_vec[..sig_len as usize]);
            } else {
                tracing::error!("CNG raw signature length is invalid: {}", sig_len);
                return Err(CryptoError::EccSignError);
            }
            sig_vec = padded;
        } else {
            sig_vec.truncate(2 * key_size);
        }
        // Extra debug: print the buffer passed to DER conversion
        tracing::debug!("CNG raw signature (padded, hex): {:02x?}", sig_vec);
        signature[..sig_vec.len()].copy_from_slice(&sig_vec);
        Ok(&signature[..sig_vec.len()])
    }

    /// Initializes a streaming sign context for the specified hash algorithm.
    ///
    /// # Arguments
    /// * `algo_handle` - The hash algorithm to use (HashAlgo).
    ///
    /// # Returns
    /// * `Result<Self::SignContext, CryptoError>` - The initialized sign context, or an error if initialization fails.
    #[allow(unsafe_code)]
    fn ecdsa_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl EcdsaCryptSignContextOp, CryptoError> {
        let degree = self.private_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_sign: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!("ecdsa_crypt_sign_init: unsupported hash algorithm for curve (degree: {}, algo: {:?})", degree, hash_algo);
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let digest_ctx = hash_algo.init()?;
        Ok(CngSignContext {
            digest_ctx,
            private_key: self.clone(),
            hash_algo,
        })
    }

    /// Returns the raw ECDSA signature size for the given hash algorithm and key.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use (HashAlgo).
    ///
    /// # Returns
    /// * `Ok(usize)` - The raw signature size in bytes (r || s format) for the specified key and hash algorithm.
    /// * `Err(CryptoError)` - If the key or hash algorithm is not supported, or if the size cannot be determined.
    #[allow(unsafe_code)]
    fn ecdsa_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError> {
        let curve_bits = self.private_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(curve_bits) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_get_signature_size: unsupported bits for curve (degree: {})",
                    curve_bits
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(hash_algo) {
            tracing::error!("ecdsa_crypt_get_signature_size: unsupported hash algorithm for curve (degree: {}, algo: {:?})", curve_bits, hash_algo);
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

impl EcdsaCryptSignContextOp for CngSignContext {
    /// Updates the sign context with additional data.
    ///
    /// # Arguments
    /// * `data` - The data to update the context with.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok on success, or an error if update fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.digest_ctx.update(data)
    }

    /// Finalizes the sign context and writes the signature.
    ///
    /// # Arguments
    /// * `signature` - The buffer to write the signature to.
    ///
    /// # Returns
    /// * `Result<usize, CryptoError>` - The size of the signature, or an error if finalization fails.
    #[allow(unsafe_code)]
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError> {
        let hash_len = self.hash_algo.hash_length();
        if hash_len == 0 {
            tracing::error!(
                "CngSignContext::finalize: unsupported hash algorithm: {:?}",
                self.hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let mut hash = vec![0u8; hash_len];
        self.digest_ctx.finish(&mut hash)?;
        let mut sig_len: u32 = 0;
        //SAFETY: Call unsafe BCRYPT API to get Signature size
        let status = unsafe {
            BCryptSignHash(
                self.private_key
                    .private_key_handle
                    .lock()
                    .unwrap()
                    .cng_private_key,
                None,
                hash.as_mut_slice(),
                None,
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (size query) failed: status={:?}", status);
            return Err(CryptoError::EccError);
        }
        if signature.len() < sig_len as usize {
            tracing::error!("ecdsa_crypt_sign: signature buffer too small");
            return Err(CryptoError::EccError);
        }
        let mut sig_vec = vec![0; sig_len as usize];
        //SAFETY: Call unsafe BCRYPT API to get Signature
        let status = unsafe {
            BCryptSignHash(
                self.private_key
                    .private_key_handle
                    .lock()
                    .unwrap()
                    .cng_private_key,
                None,
                hash.as_mut_slice(),
                Some(sig_vec.as_mut_slice()),
                &mut sig_len,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptSignHash (sign) failed: {status:?}");
            return Err(CryptoError::EccError);
        }
        let curve_bits = self
            .private_key
            .private_key_handle
            .lock()
            .unwrap()
            .curve_degree()?;
        let key_size = curve_bits.div_ceil(8) as usize;
        tracing::debug!(
            "CNG raw signature (hex): {:02x?}, sig_len: {}, expected: {}",
            sig_vec,
            sig_len,
            2 * key_size
        );
        if sig_len as usize != 2 * key_size {
            tracing::warn!(
                "CNG raw signature length {} does not match expected {}. Padding with zeros.",
                sig_len,
                2 * key_size
            );
            let mut padded = vec![0u8; 2 * key_size];
            if sig_len as usize > 0 && sig_len as usize <= 2 * key_size {
                padded[2 * key_size - sig_len as usize..]
                    .copy_from_slice(&sig_vec[..sig_len as usize]);
            } else {
                tracing::error!("CNG raw signature length is invalid: {}", sig_len);
                return Err(CryptoError::EccSignError);
            }
            sig_vec = padded;
        } else {
            sig_vec.truncate(2 * key_size);
        }
        tracing::debug!("CNG raw signature (padded, hex): {:02x?}", sig_vec);
        signature[..sig_vec.len()].copy_from_slice(&sig_vec);
        Ok(&signature[..sig_vec.len()])
    }
}

impl EcdsaCryptVerifyOp for EcPublicKey {
    /// Verifies the given signature for the data using the specified hash algorithm.
    ///
    /// # Arguments
    /// * `algo_handle` - The hash algorithm to use (HashAlgo).
    /// * `data` - The data to verify.
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if the signature is valid, or an error if verification fails.
    #[allow(unsafe_code)]
    fn ecdsa_crypt_verify(
        &self,
        algo_handle: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let degree = self.public_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_verify: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(algo_handle) {
            tracing::error!(
                "ecdsa_crypt_verify: unsupported hash algorithm for curve (degree: {}, algo: {:?})",
                degree,
                algo_handle
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }

        // Compute the digest
        let hash_len = algo_handle.hash_length();
        let mut digest = vec![0u8; hash_len];
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
    #[allow(unsafe_code)]
    fn ecdsa_crypt_verify_digest(
        &self,
        digest: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let degree = self.public_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_verify_digest: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_digest_valid_for_curve(digest) {
            tracing::error!(
                "ecdsa_crypt_verify: unsupported digest length for curve (degree: {}, digest length: {:?})",
                degree,
                digest.len()
            );
            return Err(CryptoError::EccUnsupportedDigestSize);
        }

        let key_size = self.size().map_err(|e| {
            tracing::error!("Failed to get curve key_size:{:?}", e);
            CryptoError::EcInvalidKey
        })?;
        tracing::debug!(
            "ecdsa_crypt_verify: RAW signature (hex): {:02x?}, len: {}",
            signature,
            signature.len()
        );
        if signature.len() != 2 * key_size.div_ceil(8) {
            tracing::error!(
                "ecdsa_crypt_verify: invalid signature length: {}, expected: {}",
                signature.len(),
                2 * key_size.div_ceil(8)
            );
            return Err(CryptoError::EccVerifyError);
        }
        //SAFETY: Call unsafe BCRYPT API to verify the given data with signature
        let status = unsafe {
            BCryptVerifySignature(
                self.public_key_handle.lock().unwrap().cng_public_key,
                None,
                digest,
                signature,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptVerifySignature failed: {status:?}");
            return Err(CryptoError::EccVerifyError);
        }
        Ok(())
    }

    /// Initializes a streaming verify context for the specified hash algorithm.
    ///
    /// # Arguments
    /// * `algo_handle` - The hash algorithm to use (HashAlgo).
    ///
    /// # Returns
    /// * `Result<Self::VerifyContext, CryptoError>` - The initialized verify context, or an error if initialization fails.
    #[allow(unsafe_code)]
    fn ecdsa_crypt_verify_init(
        &self,
        algo_handle: HashAlgo,
    ) -> Result<impl EcdsaCryptVerifyContextOp, CryptoError> {
        let degree = self.public_key_handle.lock().unwrap().curve_degree()?;
        let ec_curve_id = match EcCurveId::from_bits(degree) {
            Some(curve_id) => curve_id,
            None => {
                tracing::error!(
                    "ecdsa_crypt_sign: unsupported bits for curve (degree: {})",
                    degree
                );
                return Err(CryptoError::EcCurveMismatch);
            }
        };
        if !ec_curve_id.is_hash_supported_for_curve(algo_handle) {
            tracing::error!("ecdsa_crypt_verify_init: unsupported hash algorithm for curve (degree: {}, algo: {:?})", degree, algo_handle);
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let digest_ctx = algo_handle.init()?;
        Ok(CngVerifyContext {
            digest_ctx,
            public_key: self.clone(),
            hash_algo: algo_handle,
        })
    }
}

impl EcdsaCryptVerifyContextOp for CngVerifyContext {
    /// Updates the verify context with additional data.
    ///
    /// # Arguments
    /// * `data` - The data to update the context with.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok on success, or an error if update fails.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.digest_ctx.update(data)
    }

    /// Finalizes the verify context and verifies the signature.
    ///
    /// # Arguments
    /// * `signature` - The signature to verify.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if the signature is valid, or an error if verification fails.
    #[allow(unsafe_code)]
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError> {
        let hash_len = self.hash_algo.hash_length();
        if hash_len == 0 {
            tracing::error!(
                "CngVerifyContext::finalize: unsupported hash algorithm: {:?}",
                self.hash_algo
            );
            return Err(CryptoError::EccUnsupportedHashAlgorithm);
        }
        let mut digest = vec![0u8; hash_len];
        self.digest_ctx.finish(&mut digest)?;
        let key_size = self
            .public_key
            .public_key_handle
            .lock()
            .unwrap()
            .curve_degree()
            .map_err(|e| {
                tracing::error!("finalize : Failed to get curve degree for verify : {:?}", e);
                CryptoError::EcInvalidKey
            })?
            .div_ceil(8);
        tracing::debug!(
            "CngVerifyContext::finalize: DER signature (hex): {:02x?}, len: {}",
            signature,
            signature.len()
        );
        if signature.len() != 2 * key_size as usize {
            tracing::error!(
                "CngVerifyContext::finalize: invalid signature length: {}, expected: {}",
                signature.len(),
                2 * key_size
            );
            return Err(CryptoError::EccVerifyError);
        }
        //SAFETY: Call unsafe BCRYPT API to verify the signature
        let status = unsafe {
            BCryptVerifySignature(
                self.public_key
                    .public_key_handle
                    .lock()
                    .unwrap()
                    .cng_public_key,
                None,
                &digest,
                signature,
                BCRYPT_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptVerifySignature failed: {status:?}");
            return Err(CryptoError::EccVerifyError);
        }
        Ok(())
    }
}
