// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

use std::slice;

use windows::core::PCWSTR;
use windows::Win32::Foundation::NTSTATUS;
use windows::Win32::Foundation::STATUS_SUCCESS;
use windows::Win32::Security::Cryptography::*;

use super::*;
use crate::secretkey::*;

/// Handler for a CNG HKDF key handle. Owns the symmetric key handle and ensures cleanup.
///
/// This struct wraps a Windows CNG symmetric key handle used in HKDF operations.
/// It implements RAII (Resource Acquisition Is Initialization) pattern to ensure
/// proper cleanup of the key handle when the struct is dropped.
struct CngHkdfKeyHandle {
    /// The handle to the CNG symmetric key used for HKDF operations.
    key_handle: BCRYPT_KEY_HANDLE,
}

/// Handler for a CNG HKDF algorithm provider. Owns the algorithm provider handle and ensures cleanup.
///
/// This struct wraps a Windows CNG algorithm provider handle specifically for HKDF operations.
/// It implements RAII (Resource Acquisition Is Initialization) pattern to ensure proper cleanup
/// of the algorithm provider handle when the struct is dropped.
struct CngHkdfAlgoHandler {
    /// The handle to the CNG algorithm provider.
    hkdf_algo_handle: BCRYPT_ALG_HANDLE,
}

impl CngHkdfAlgoHandler {
    // Methods for CngHkdfAlgoHandler can be added here if needed
}

impl Drop for CngHkdfKeyHandle {
    /// Cleans up the CNG secret handle when the handler is dropped.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptDestroySecret; the handle is valid and owned by this struct
        let status = unsafe { BCryptDestroyKey(self.key_handle) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptDestroySecret failed: {status:?}");
        }
    }
}

impl Drop for CngHkdfAlgoHandler {
    /// Cleans up the CNG algorithm provider handle when the handler is dropped.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: calls BCryptCloseAlgorithmProvider; the handle is valid and owned by this struct
        let status = unsafe { BCryptCloseAlgorithmProvider(self.hkdf_algo_handle, 0) };
        if status != STATUS_SUCCESS {
            tracing::error!("BCryptCloseAlgorithmProvider failed: {status:?}");
        }
    }
}

impl HkdfKeyDeriveOps for SecretKey {
    /// Performs HKDF key derivation using Windows CNG APIs.
    ///
    /// This function implements the complete HKDF algorithm as defined in RFC 5869
    /// using Windows Cryptography Next Generation (CNG) APIs. It follows the
    /// recommended two-phase approach:
    ///
    /// 1. **Extract Phase**: Uses `BCryptSetProperty` with `BCRYPT_HKDF_SALT_AND_FINALIZE`
    ///    to combine the input key material (IKM) with salt and create a pseudorandom key (PRK).
    ///
    /// 2. **Expand Phase**: Uses `BCryptKeyDerivation` with the info parameter to expand
    ///    the PRK into the desired output key material (OKM).
    ///
    /// # Implementation Details
    /// - Opens a CNG HKDF algorithm provider using `BCryptOpenAlgorithmProvider`
    /// - Creates a symmetric key from the input key material using `BCryptGenerateSymmetricKey`
    /// - Sets the hash algorithm using `BCRYPT_HKDF_HASH_ALGORITHM` property
    /// - Performs Extract phase by setting salt with `BCRYPT_HKDF_SALT_AND_FINALIZE`
    /// - Performs Expand phase using `BCryptKeyDerivation` with info parameter
    /// - All CNG handles are properly managed with RAII pattern for automatic cleanup
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use (SHA-1, SHA-256, SHA-384, SHA-512).
    /// * `salt` - Optional salt value for the extract phase. If None, empty salt is used.
    /// * `info` - Optional context-specific information for the expand phase.
    /// * `out_len` - The desired length of the derived key in bytes.
    /// * `secret_key` - Mutable buffer to store the derived key. Must be at least `out_len` bytes.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - A slice of the derived key with length `out_len` on success.
    /// * `Err(CryptoError)` - If the derivation fails or parameters are invalid.
    ///
    /// # Errors
    /// * `CryptoError::HkdfOutputLengthZero` - If the requested output length is zero.
    /// * `CryptoError::HkdfOutputBufferTooSmall` - If the output buffer is smaller than `out_len`.
    /// * `CryptoError::HkdfBackendFail` - If CNG algorithm provider opening fails.
    /// * `CryptoError::HkdfExtractFailed` - If key generation, hash algorithm setting, or salt finalization fails.
    /// * `CryptoError::HkdfExpandFailed` - If key derivation or output length validation fails.
    ///
    /// # Safety
    /// This function uses unsafe code to interface with Windows CNG APIs. All unsafe
    /// operations are carefully validated and documented with safety comments.
    #[allow(unsafe_code)]
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
            tracing::error!("Output buffer too small for requested length");
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

        // Open HKDF algorithm provider
        let mut algo_handle = CngHkdfAlgoHandler {
            hkdf_algo_handle: BCRYPT_ALG_HANDLE::default(),
        };

        // SAFETY: calls BCryptOpenAlgorithmProvider; the handle is valid and owned by this struct
        let status: NTSTATUS = unsafe {
            BCryptOpenAlgorithmProvider(
                &mut algo_handle.hkdf_algo_handle,
                BCRYPT_HKDF_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to open HKDF algo handle: {:?}", status);
            return Err(CryptoError::HkdfBackendFail);
        }

        // Create a symmetric key from the input key material (IKM)
        let mut cng_key_handle = CngHkdfKeyHandle {
            key_handle: BCRYPT_KEY_HANDLE::default(),
        };

        // SAFETY: calls BCryptGenerateSymmetricKey; all handles are valid and owned by this function
        let status = unsafe {
            BCryptGenerateSymmetricKey(
                algo_handle.hkdf_algo_handle,
                &mut cng_key_handle.key_handle,
                None,
                &self.kdk,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to generate symmetric key: {:?}", status);
            // Check for CNG-specific limitations
            if status.0 == -1073741811_i32 {
                // STATUS_INVALID_PARAMETER for IKM size
                tracing::error!("IKM size may exceed CNG limits ({}  bytes)", self.kdk.len());
            }
            return Err(CryptoError::HkdfExtractFailed);
        }

        // HKDF Extract Phase: Set hash algorithm and salt, then finalize
        // Step 1: Set the hash algorithm for HKDF
        let hash_algo_str = get_hash_algo_str(hash_algo)?;
        let hash_algo_bytes = pcwstr_to_u8_vec(hash_algo_str);

        // SAFETY: calls BCryptSetProperty to set HKDF hash algorithm; all handles and data are valid
        let status = unsafe {
            BCryptSetProperty(
                cng_key_handle.key_handle.into(),
                BCRYPT_HKDF_HASH_ALGORITHM,
                &hash_algo_bytes,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to set HKDF hash algorithm: {:?}", status);
            return Err(CryptoError::HkdfExtractFailed);
        }

        // Step 2: Set salt and finalize the key handle (Extract phase)
        // Use BCRYPT_HKDF_SALT_AND_FINALIZE since we're treating input as IKM
        let default_salt = [];
        let salt_bytes = salt.unwrap_or(&default_salt);

        // SAFETY: calls BCryptSetProperty to set salt and finalize; all handles and data are valid
        let status = unsafe {
            BCryptSetProperty(
                cng_key_handle.key_handle.into(),
                BCRYPT_HKDF_SALT_AND_FINALIZE,
                salt_bytes,
                0,
            )
        };
        if status != STATUS_SUCCESS {
            tracing::error!("Failed to set HKDF salt and finalize: {:?}", status);
            return Err(CryptoError::HkdfExtractFailed);
        }

        // HKDF Expand Phase: Use BCryptKeyDerivation with info parameter
        let default_info = [];
        let info_bytes = info.unwrap_or(&default_info);

        let mut params = Vec::new();

        // Add info parameter for expansion if provided
        if !info_bytes.is_empty() {
            params.push(BCryptBuffer {
                cbBuffer: info_bytes.len() as u32,
                BufferType: KDF_HKDF_INFO,
                pvBuffer: info_bytes.as_ptr() as *mut _,
            });
        }

        let param_list = if params.is_empty() {
            None
        } else {
            Some(BCryptBufferDesc {
                ulVersion: BCRYPTBUFFER_VERSION,
                cBuffers: params.len() as u32,
                pBuffers: params.as_ptr() as *mut _,
            })
        };

        // Perform key derivation (Expand phase)
        let mut bytes_copied: u32 = 0;
        // SAFETY: calls BCryptKeyDerivation; all handles and buffers are valid and properly sized
        let status = unsafe {
            BCryptKeyDerivation(
                cng_key_handle.key_handle,
                param_list.as_ref().map(|p| p as *const _),
                &mut secret_key[..out_len],
                &mut bytes_copied,
                0,
            )
        };

        if status != STATUS_SUCCESS {
            tracing::error!("BCryptKeyDerivation failed: {:?}", status);
            // Check for CNG-specific output length limitations
            if status.0 == -1073741823_i32 {
                // STATUS_UNSUCCESSFUL for output size
                tracing::error!("Output length {} may exceed CNG limits", out_len);
                return Err(CryptoError::HkdfOutputTooLarge);
            }
            return Err(CryptoError::HkdfExpandFailed);
        }

        if bytes_copied as usize != out_len {
            tracing::error!("Key derivation size mismatch");
            return Err(CryptoError::HkdfExpandFailed);
        }

        Ok(&secret_key[..out_len])
    }
}

/// Maps hash algorithm enum to corresponding CNG algorithm constant.
///
/// This function converts the internal HashAlgo enum values to the appropriate
/// Windows CNG algorithm identifiers used by BCrypt functions.
///
/// # Arguments
/// * `hash_algo` - The hash algorithm enum value to convert.
///
/// # Returns
/// * `Ok(PCWSTR)` - The corresponding CNG algorithm identifier on success.
/// * `Err(CryptoError::HkdfUnsupportedHashAlgorithm)` - If the hash algorithm is not supported.
///
/// # Supported Algorithms
/// * `HashAlgo::Sha1` -> `BCRYPT_SHA1_ALGORITHM`
/// * `HashAlgo::Sha256` -> `BCRYPT_SHA256_ALGORITHM`
/// * `HashAlgo::Sha384` -> `BCRYPT_SHA384_ALGORITHM`
/// * `HashAlgo::Sha512` -> `BCRYPT_SHA512_ALGORITHM`
// Map hash algorithm enum to CNG constant
fn get_hash_algo_str(hash_algo: HashAlgo) -> Result<PCWSTR, CryptoError> {
    let hash_algo_id = match hash_algo {
        HashAlgo::Sha1 => BCRYPT_SHA1_ALGORITHM,
        HashAlgo::Sha256 => BCRYPT_SHA256_ALGORITHM,
        HashAlgo::Sha384 => BCRYPT_SHA384_ALGORITHM,
        HashAlgo::Sha512 => BCRYPT_SHA512_ALGORITHM,
    };
    tracing::debug!("Selected hash algorithm for HKDF");
    Ok(hash_algo_id)
}

/// Converts a PCWSTR to a Vec<u8> by reinterpreting the UTF-16 memory as bytes.
///
/// This function is used to convert Windows CNG algorithm identifiers (which are
/// null-terminated UTF-16 strings) into byte vectors that can be passed to
/// BCryptSetProperty functions. The conversion includes the null terminator.
///
/// # Arguments
/// * `pcwstr` - A null-terminated UTF-16 string pointer (PCWSTR).
///
/// # Returns
/// * `Vec<u8>` - A byte vector containing the UTF-16 string data including null terminator.
///
/// # Safety
/// This function uses unsafe code to:
/// - Dereference the raw pointer to count UTF-16 code units
/// - Create a slice from raw parts for both UTF-16 and byte interpretation
/// - The caller must ensure the PCWSTR points to a valid null-terminated UTF-16 string
///
/// # Implementation Details
/// - Counts UTF-16 code units until null terminator is found
/// - Includes the null terminator in the final byte vector
/// - Reinterprets the UTF-16 memory directly as bytes (little-endian)
#[allow(unsafe_code)]
fn pcwstr_to_u8_vec(pcwstr: PCWSTR) -> Vec<u8> {
    // SAFETY: use unsafe section to convert PCWSTR to vec
    unsafe {
        let mut len = 0;
        let ptr = pcwstr.0;

        // Count UTF-16 code units until null terminator
        while *ptr.add(len) != 0 {
            len += 1;
        }

        // Include null terminator
        let u16_slice = slice::from_raw_parts(ptr, len + 1);

        // Convert &[u16] to &[u8] by reinterpreting the memory
        let byte_ptr = u16_slice.as_ptr() as *const u8;
        let byte_len = u16_slice.len() * 2;

        slice::from_raw_parts(byte_ptr, byte_len).to_vec()
    }
}
