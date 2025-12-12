// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG (Cryptography Next Generation) HMAC implementation for the AziHSM project.
//!
//! This module provides HMAC (Hash-based Message Authentication Code) signing and verification using the Windows CNG API.
//! It supports both one-shot and streaming (multi-part) HMAC operations for SHA-1, SHA-256, SHA-384, and SHA-512.
//!
//! The main goal is to provide a safe Rust abstraction over the Windows CNG primitives for HMAC, handling resource management,
//! error propagation, and correct usage patterns. This file is intended for use on Windows platforms only.
//!
//! Key features:
//! - One-shot HMAC sign/verify (single call for all data)
//! - Streaming HMAC sign/verify (multi-part updates, then finalize)
//! - Automatic resource cleanup (Drop impls)
//! - Error handling and tracing for debugging
//! - Enforces non-empty data for streaming updates to catch logic errors

#![warn(missing_docs)]

use windows::core::PCWSTR;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::sha::*;

/// Handler for a CNG HMAC hash operation. Owns the hash handle and ensures cleanup.
struct CngHmacHandler {
    /// The handle to the CNG hash object.
    hmac_handle: BCRYPT_HASH_HANDLE,
}

/// Handler for a CNG HMAC algorithm provider. Owns the algorithm provider handle and ensures cleanup.
struct CngHmacAlgoHandler {
    /// The handle to the CNG algorithm provider.
    hmac_algo_handle: BCRYPT_ALG_HANDLE,
}

impl CngHmacAlgoHandler {
    /// Maps a HashAlgo to a CNG algorithm identifier.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(PCWSTR)` with the algorithm identifier on success.
    /// * `Err(CryptoError)` if the algorithm is not supported.
    fn hash_algo_to_alg_id(hash_algo: HashAlgo) -> Result<PCWSTR, CryptoError> {
        match hash_algo {
            HashAlgo::Sha1 => Ok(BCRYPT_SHA1_ALGORITHM),
            HashAlgo::Sha256 => Ok(BCRYPT_SHA256_ALGORITHM),
            HashAlgo::Sha384 => Ok(BCRYPT_SHA384_ALGORITHM),
            HashAlgo::Sha512 => Ok(BCRYPT_SHA512_ALGORITHM),
        }
    }
}

impl Drop for CngHmacHandler {
    /// Cleans up the CNG hash handle when the handler is dropped.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroyHash; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyHash(self.hmac_handle) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroyHash failed: {status:?}");
        }
    }
}

impl Drop for CngHmacAlgoHandler {
    /// Cleans up the CNG algorithm provider handle when the handler is dropped.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptCloseAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe { BCryptCloseAlgorithmProvider(self.hmac_algo_handle, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptCloseAlgorithmProvider failed: {status:?}");
        }
    }
}

// Implementation of HMAC signing operations for HmacKey using Windows CNG.
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
    /// * `Err(CryptoError)` if signing fails or key is empty.
    #[allow(unsafe_code)]
    fn hmac_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError> {
        // Reject empty key for consistency with OpenSSL and security best practices
        if self.key.is_empty() {
            tracing::error!("HMAC sign called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }

        // Enforce key size bounds
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

        // Set HMAC flag for algorithm provider
        let dwflags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
        let hash_size = hash_algo.hash_length();
        // Check if signature buffer is large enough
        if hash_size > signature.len() {
            tracing::error!("Invalid hash size :{:#X}", hash_size);
            Err(CryptoError::HmacSignatureBufferTooSmall)?
        }
        // Map hash algorithm to CNG algorithm identifier
        let algo_id = CngHmacAlgoHandler::hash_algo_to_alg_id(hash_algo)?;
        // Open algorithm provider
        let mut algo_handle: CngHmacAlgoHandler = CngHmacAlgoHandler {
            hmac_algo_handle: BCRYPT_ALG_HANDLE::default(),
        };
        // SAFETY: calls BCryptOpenAlgorithmProvider; the handle is valid and owned by this struct
        let status: NTSTATUS = unsafe {
            BCryptOpenAlgorithmProvider(&mut algo_handle.hmac_algo_handle, algo_id, None, dwflags)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open hamc algo handle : {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        let status: NTSTATUS;
        // SAFETY: calculate hash by calling unsafe Windows CNG BCryptHash
        unsafe {
            status = BCryptHash(
                algo_handle.hmac_algo_handle,
                Some(self.key.as_slice()),
                data,
                signature,
            );
        }
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to calculate handle : {:#X}", status.0);
            Err(CryptoError::HmacSignFail)?
        }
        Ok(&signature[..hash_size])
    }

    /// Initializes a streaming signing context for multi-part signing.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(CngHmacSignContext)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    #[allow(unsafe_code)]
    fn hmac_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptSignContextOp, CryptoError> {
        // Reject empty key for consistency with OpenSSL and security best practices
        if self.key.is_empty() {
            tracing::error!("HMAC sign_init called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Enforce key size bounds
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC sign_init key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC sign_init key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }

        let dwflags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
        let algo_id = match CngHmacAlgoHandler::hash_algo_to_alg_id(hash_algo) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Invalid hash algorithm: {:?}", hash_algo);
                return Err(e);
            }
        };
        let mut algo_handle = CngHmacAlgoHandler {
            hmac_algo_handle: BCRYPT_ALG_HANDLE::default(),
        };
        // SAFETY: calls BCryptOpenAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut algo_handle.hmac_algo_handle, algo_id, None, dwflags)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open HMAC algo handle: {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        let mut hmac_handle = CngHmacHandler {
            hmac_handle: BCRYPT_HASH_HANDLE::default(),
        };
        // SAFETY: calls BCryptCreateHash; the handle is valid and owned by this struct
        let status = unsafe {
            BCryptCreateHash(
                algo_handle.hmac_algo_handle,
                &mut hmac_handle.hmac_handle,
                None,
                Some(self.key.as_slice()),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to create HMAC hash handle: {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        Ok(CngHmacSignContext { hmac_handle })
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
        Ok(hash_algo.hash_length())
    }
}

/// Streaming HMAC signing context. Owns the hash handle for multi-part signing.
struct CngHmacSignContext {
    /// The CNG HMAC hash handle.
    hmac_handle: CngHmacHandler,
}

// Implementation of streaming HMAC signing operations.
impl HmacCryptSignContextOp for CngHmacSignContext {
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
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // We do not allow empty data for streaming HMAC updates.
        // This is to prevent accidental no-op updates and to catch logic errors early.
        if data.is_empty() {
            tracing::error!("HMAC update called with empty data slice");
            return Err(CryptoError::HmacSignFail);
        }
        // SAFETY: calls BCryptHashData to update the hash with more data
        let status = unsafe { BCryptHashData(self.hmac_handle.hmac_handle, data, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to update HMAC hash: {:?}", status);
            return Err(CryptoError::HmacSignFail);
        }
        Ok(())
    }
    /// Finalizes the signature and writes it to the output buffer.
    ///
    /// # Arguments
    /// * `signature` - The output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(&[u8])` with the signature on success.
    /// * `Err(CryptoError)` if finalization fails or the buffer is too small.
    #[allow(unsafe_code)]
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError> {
        // Query the hash size using BCryptGetProperty to determine how many bytes the HMAC will produce
        let mut hash_size: u32 = 0;
        let mut result_size: u32 = 0;
        // SAFETY: calls BCryptGetProperty to get the hash length
        let status = unsafe {
            BCryptGetProperty(
                self.hmac_handle.hmac_handle,
                BCRYPT_HASH_LENGTH,
                Some(std::slice::from_mut(&mut hash_size).align_to_mut::<u8>().1),
                &mut result_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get HMAC hash size: {:?}", status);
            return Err(CryptoError::HmacSignFail);
        }
        // Check if the provided signature buffer is large enough
        if (signature.len() as u32) < hash_size {
            tracing::error!(
                "Signature buffer too small: required {}, got {}",
                hash_size,
                signature.len()
            );
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // SAFETY: calls BCryptFinishHash to finalize the hash and write the signature
        let status = unsafe { BCryptFinishHash(self.hmac_handle.hmac_handle, signature, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to finalize HMAC hash: {:?}", status);
            return Err(CryptoError::HmacSignFail);
        }
        // Return the signature slice up to the hash size
        Ok(&signature[..hash_size as usize])
    }
}

// Implementation of HMAC verification operations for HmacKey using Windows CNG.
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
    #[allow(unsafe_code)]
    fn hmac_crypt_verify(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if self.key.is_empty() {
            tracing::error!("HMAC hmac_crypt_verify called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Enforce key size bounds
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

        // Set HMAC flag for algorithm provider
        let dwflags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
        let hash_size = hash_algo.hash_length();
        // Check if the provided signature length matches the expected hash size
        if signature.len() != hash_size {
            tracing::error!(
                "Signature length mismatch: expected {}, got {}",
                hash_size,
                signature.len()
            );
            return Err(CryptoError::HmacSignatureLengthMismatch);
        }
        // Map hash algorithm to CNG algorithm identifier
        let algo_id = match CngHmacAlgoHandler::hash_algo_to_alg_id(hash_algo) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Invalid hash algorithm: {:?}", hash_algo);
                return Err(e);
            }
        };
        // Open algorithm provider
        let mut algo_handle = CngHmacAlgoHandler {
            hmac_algo_handle: BCRYPT_ALG_HANDLE::default(),
        };
        // SAFETY: calls BCryptOpenAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut algo_handle.hmac_algo_handle, algo_id, None, dwflags)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open HMAC algo handle: {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        // Prepare a buffer to hold the calculated signature
        let mut calc_signature = vec![0u8; hash_size];
        // SAFETY: calculate hash by calling unsafe Windows CNG BCryptHash
        let status = unsafe {
            BCryptHash(
                algo_handle.hmac_algo_handle,
                Some(self.key.as_slice()),
                data,
                &mut calc_signature,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to calculate HMAC: {:#X}", status.0);
            return Err(CryptoError::HmacVerifyFail);
        }
        // Compare the calculated signature with the provided signature
        if &calc_signature[..] != signature {
            tracing::error!("HMAC verification failed: signature mismatch");
            return Err(CryptoError::HmacSignatureMismatch);
        }
        Ok(())
    }

    /// Initializes a streaming verification context for multi-part verification.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(CngHmacVerifyContext)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    #[allow(unsafe_code)]
    fn hmac_crypt_verify_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptVerifyContextOp, CryptoError> {
        // Reject empty key for consistency with OpenSSL and security best practices
        if self.key.is_empty() {
            tracing::error!("HMAC verify_init called with empty key");
            return Err(CryptoError::HmacKeyEmpty);
        }
        // Enforce key size bounds
        let range = HmacKey::get_lower_upper_key_size(hash_algo);
        if self.key.len() < range.lower_bound {
            tracing::error!(
                "HMAC verify_init key too short: {} < {}",
                self.key.len(),
                range.lower_bound
            );
            return Err(CryptoError::HmacKeyTooShort);
        }
        if self.key.len() > range.upper_bound {
            tracing::error!(
                "HMAC verify_init key too long: {} > {}",
                self.key.len(),
                range.upper_bound
            );
            return Err(CryptoError::HmacKeyTooLong);
        }
        // Set HMAC flag for algorithm provider
        let dwflags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
        // Map hash algorithm to CNG algorithm identifier
        let algo_id = match CngHmacAlgoHandler::hash_algo_to_alg_id(hash_algo) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("Invalid hash algorithm: {:?}", hash_algo);
                return Err(e);
            }
        };
        // Open algorithm provider
        let mut algo_handle = CngHmacAlgoHandler {
            hmac_algo_handle: BCRYPT_ALG_HANDLE::default(),
        };
        // SAFETY: calls BCryptOpenAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut algo_handle.hmac_algo_handle, algo_id, None, dwflags)
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open HMAC algo handle: {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        // Create a new HMAC hash handle for streaming
        let mut hmac_handle = CngHmacHandler {
            hmac_handle: BCRYPT_HASH_HANDLE::default(),
        };
        // SAFETY: calls BCryptCreateHash; the handle is valid and owned by this struct
        let status = unsafe {
            BCryptCreateHash(
                algo_handle.hmac_algo_handle,
                &mut hmac_handle.hmac_handle,
                None,
                Some(self.key.as_slice()),
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to create HMAC hash handle: {:?}", status);
            return Err(CryptoError::HmacBackendFail);
        }
        Ok(CngHmacVerifyContext { hmac_handle })
    }
}

/// Streaming HMAC verification context. Owns the hash handle for multi-part verification.
struct CngHmacVerifyContext {
    /// The CNG HMAC hash handle.
    hmac_handle: CngHmacHandler,
}

/// Streaming HMAC verification operations.
impl HmacCryptVerifyContextOp for CngHmacVerifyContext {
    /// Updates the verification context with more data.
    ///
    /// # Arguments
    /// * `data` - The data to add to the HMAC verification.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails or if data is empty.
    ///
    /// # Note
    /// Empty data is not allowed for streaming HMAC updates. This is to prevent accidental no-op updates and to catch logic errors early.
    #[allow(unsafe_code)]
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        // Check if data is empty; return error if so
        if data.is_empty() {
            tracing::error!("HMAC verify update called with empty data slice");
            return Err(CryptoError::HmacVerifyFail);
        }
        // SAFETY: calls BCryptHashData to update the hash with more data
        let status = unsafe { BCryptHashData(self.hmac_handle.hmac_handle, data, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to update HMAC hash (verify): {:?}", status);
            return Err(CryptoError::HmacVerifyFail);
        }
        Ok(())
    }
    /// Finalizes the verification and checks the signature.
    ///
    /// # Arguments
    /// * `signature` - The signature to check against.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails or the signature is invalid.
    #[allow(unsafe_code)]
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError> {
        // Query the hash size using BCryptGetProperty to determine the expected signature length
        let mut hash_size: u32 = 0;
        let mut result_size: u32 = 0;
        // SAFETY: calls BCryptGetProperty to get the hash length
        let status = unsafe {
            BCryptGetProperty(
                self.hmac_handle.hmac_handle,
                BCRYPT_HASH_LENGTH,
                Some(std::slice::from_mut(&mut hash_size).align_to_mut::<u8>().1),
                &mut result_size,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to get HMAC hash size (verify): {:?}", status);
            return Err(CryptoError::HmacVerifyFail);
        }
        // Check if the provided signature buffer is large enough
        if (signature.len() as u32) < hash_size {
            tracing::error!(
                "Signature buffer too small (verify): required {}, got {}",
                hash_size,
                signature.len()
            );
            return Err(CryptoError::HmacSignatureBufferTooSmall);
        }
        // Prepare a buffer to hold the calculated signature
        let mut calc_signature = vec![0u8; hash_size as usize];
        // SAFETY: calls BCryptFinishHash to finalize the hash and write the signature
        let status =
            unsafe { BCryptFinishHash(self.hmac_handle.hmac_handle, &mut calc_signature, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to finalize HMAC hash (verify): {:?}", status);
            return Err(CryptoError::HmacVerifyFail);
        }
        // Compare the calculated signature with the provided signature
        if calc_signature[..] != signature[..hash_size as usize] {
            tracing::error!("HMAC streaming verification failed: signature mismatch");
            return Err(CryptoError::HmacSignatureMismatch);
        }
        Ok(())
    }
}
