// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG (Cryptography API: Next Generation) support for AES operations.
// SAFETY: This module uses FFI to call the Windows CNG API, which requires unsafe code for handle management and cryptographic operations.
// All unsafe blocks are carefully audited to ensure valid pointers, buffer sizes, and resource cleanup. RAII wrappers are used for handle safety.

#![allow(unsafe_code)]

// use tracing::instrument;
use windows::Win32::Security::Cryptography::*;

use crate::errors::ManticoreError;

/// RAII wrapper for BCRYPT_ALG_HANDLE
pub struct CngAlgoHandle {
    cng_algo_handle: BCRYPT_ALG_HANDLE,
}

impl CngAlgoHandle {
    /// Creates a new CngAlgoHandle for AES in ECB mode.
    ///
    /// # Errors
    /// Returns `ManticoreError` if the algorithm provider cannot be opened or configured.
    ///
    /// # Safety
    /// This function uses unsafe Windows API calls to manage cryptographic handles.
    pub fn new() -> Result<Self, ManticoreError> {
        #[allow(unsafe_code)]
        // SAFETY: This block calls Windows CNG APIs to open and configure an AES algorithm provider handle.
        // The handle is managed by RAII and closed in Drop. All pointers and slices are valid and sizes are correct.
        unsafe {
            let mut alg_handle = BCRYPT_ALG_HANDLE::default();

            // Open AES algorithm provider in ECB mode
            let result = BCryptOpenAlgorithmProvider(
                &mut alg_handle,
                BCRYPT_AES_ALGORITHM,
                None,
                BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS(0),
            );

            if !result.is_ok() {
                tracing::error!(
                    "Windows CNG API: Failed to get AES ECB algorithm provider handle: 0x{:08x}",
                    result.0
                );
                Err(ManticoreError::InternalError)?;
            }

            // Set chaining mode to ECB
            let ecb_mode = BCRYPT_CHAIN_MODE_ECB;
            let ecb_mode_slice = {
                let ptr = ecb_mode.as_ptr();
                let mut len = 0;
                // Count wide characters until null terminator
                while *ptr.add(len) != 0 {
                    len += 1;
                }
                // Convert to byte slice (each wide char is 2 bytes)
                std::slice::from_raw_parts(ptr as *const u8, (len + 1) * 2)
            };

            let result = BCryptSetProperty(
                BCRYPT_HANDLE(alg_handle.0),
                BCRYPT_CHAINING_MODE,
                ecb_mode_slice,
                0,
            );

            if !result.is_ok() {
                let _ = BCryptCloseAlgorithmProvider(alg_handle, 0);
                tracing::error!(
                    "Windows CNG API: Failed to set chaining mode to ECB: 0x{:08x}",
                    result.0
                );
                Err(ManticoreError::InternalError)?;
            }

            Ok(CngAlgoHandle {
                cng_algo_handle: alg_handle,
            })
        }
    }

    /// Returns the underlying BCRYPT_ALG_HANDLE.
    ///
    /// # Returns
    /// The BCRYPT_ALG_HANDLE managed by this wrapper.
    pub fn handle(&self) -> BCRYPT_ALG_HANDLE {
        self.cng_algo_handle
    }
}

impl Drop for CngAlgoHandle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Closing the algorithm provider is required to avoid resource leaks. The handle is valid if constructed.
        unsafe {
            let _ = BCryptCloseAlgorithmProvider(self.cng_algo_handle, 0);
        }
    }
}

/// RAII wrapper for BCRYPT_KEY_HANDLE
pub struct CngKeyHandle {
    cng_key_handle: BCRYPT_KEY_HANDLE,
}

impl CngKeyHandle {
    /// Creates a new CngKeyHandle by generating a symmetric key from the provided algorithm handle and key data.
    ///
    /// # Arguments
    /// * `alg_handle` - The BCRYPT_ALG_HANDLE for the AES algorithm.
    /// * `key_data` - The raw key bytes.
    ///
    /// # Returns
    /// A Result containing the CngKeyHandle or a ManticoreError if key generation fails.
    pub fn new(alg_handle: BCRYPT_ALG_HANDLE, key_data: &[u8]) -> Result<Self, ManticoreError> {
        // SAFETY: This block calls Windows CNG APIs to generate a symmetric key handle from valid input.
        // The handle is managed by RAII and destroyed in Drop. Key data is a valid byte slice.
        unsafe {
            let mut key_handle = BCRYPT_KEY_HANDLE::default();
            let result = BCryptGenerateSymmetricKey(alg_handle, &mut key_handle, None, key_data, 0);

            if !result.is_ok() {
                tracing::error!(
                    "Windows CNG API: Failed to get the symmetric key handle: 0x{:08x}",
                    result.0
                );
                Err(ManticoreError::AesGenerateError)?;
            }

            Ok(CngKeyHandle {
                cng_key_handle: key_handle,
            })
        }
    }

    /// Returns the underlying BCRYPT_KEY_HANDLE.
    ///
    /// # Returns
    /// The BCRYPT_KEY_HANDLE managed by this wrapper.
    pub fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.cng_key_handle
    }
}

impl Drop for CngKeyHandle {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Destroying the key handle is required to avoid resource leaks. The handle is valid if constructed.
        unsafe {
            let _ = BCryptDestroyKey(self.cng_key_handle);
        }
    }
}

/// Helper function for encrypting a single buffer
/// Encrypts a single buffer using AES-XTS mode with the provided key handles and tweak.
///
/// # Arguments
/// * `key1_handle` - Handle to the first AES key.
/// * `key2_handle` - Handle to the second AES key (used for tweak).
/// * `plaintext` - The data to encrypt. Has to be multiple of 16 bytes.
/// * `tweak` - The 16-byte tweak value.
/// * `output` - Buffer to write the encrypted data into.
///
/// # Errors
/// Returns `ManticoreError` if encryption fails.
pub fn encrypt_single_buffer(
    key1_handle: BCRYPT_KEY_HANDLE,
    key2_handle: BCRYPT_KEY_HANDLE,
    plaintext: &[u8],
    tweak: &[u8; 16],
    output: &mut [u8],
) -> Result<(), ManticoreError> {
    // XTS encryption algorithm
    // Encrypt the initial tweak with key2 to get T
    let mut t = aes_encrypt_block(key2_handle, tweak)?;

    if plaintext.len() % 16 != 0 {
        return Err(ManticoreError::AesEncryptError);
    }

    // Process each 16-byte block
    for (i, chunk) in plaintext.chunks(16).enumerate() {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR block with T
        for j in 0..16 {
            block[j] ^= t[j];
        }

        // Encrypt with key1
        let encrypted_block = aes_encrypt_block(key1_handle, &block)?;

        // XOR result with T again
        for j in 0..16 {
            output[i * 16 + j] = encrypted_block[j] ^ t[j];
        }

        // Multiply T by α (primitive element in GF(2^128)) for next block
        if i < plaintext.len() / 16 - 1 {
            t = gf128_mul_alpha(t);
        }
    }

    Ok(())
}

/// Helper function for decrypting a single buffer
/// Decrypts a single buffer using AES-XTS mode with the provided key handles and tweak.
///
/// # Arguments
/// * `key1_handle` - Handle to the first AES key.
/// * `key2_handle` - Handle to the second AES key (used for tweak).
/// * `ciphertext` - The encrypted data to decrypt. Has to be multiple of 16 bytes.
/// * `tweak` - The 16-byte tweak value.
/// * `output` - Buffer to write the decrypted data into.
///
/// # Errors
/// Returns `ManticoreError` if decryption fails.
pub fn decrypt_single_buffer(
    key1_handle: BCRYPT_KEY_HANDLE,
    key2_handle: BCRYPT_KEY_HANDLE,
    ciphertext: &[u8],
    tweak: &[u8; 16],
    output: &mut [u8],
) -> Result<(), ManticoreError> {
    // XTS decryption algorithm
    // Encrypt the initial tweak with key2 to get T
    let mut t = aes_encrypt_block(key2_handle, tweak)?;

    if ciphertext.len() % 16 != 0 {
        return Err(ManticoreError::AesDecryptError);
    }

    // Process each 16-byte block
    for (i, chunk) in ciphertext.chunks(16).enumerate() {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);

        // XOR block with T
        for j in 0..16 {
            block[j] ^= t[j];
        }

        // Decrypt with key1
        let decrypted_block = aes_decrypt_block(key1_handle, &block)?;

        // XOR result with T again
        for j in 0..16 {
            output[i * 16 + j] = decrypted_block[j] ^ t[j];
        }

        // Multiply T by α for next block
        if i < ciphertext.len() / 16 - 1 {
            t = gf128_mul_alpha(t);
        }
    }

    Ok(())
}

// Helper function for AES block encryption
fn aes_encrypt_block(
    key_handle: BCRYPT_KEY_HANDLE,
    block: &[u8],
) -> Result<[u8; 16], ManticoreError> {
    #[allow(unsafe_code)]
    // SAFETY: Calls BCryptEncrypt with valid key handle and block pointers. Output buffer is sized for a 16-byte block.
    unsafe {
        let mut output = [0u8; 16];
        let mut cb_result = 0u32;

        let result = BCryptEncrypt(
            key_handle,
            Some(block),
            None,
            None, // No IV for ECB mode
            Some(&mut output),
            &mut cb_result,
            BCRYPT_FLAGS(0),
        );

        if !result.is_ok() {
            tracing::error!(
                "Windows CNG API: AES block encryption failed: 0x{:08x}",
                result.0
            );
            return Err(ManticoreError::AesEncryptError);
        }

        Ok(output)
    }
}

// Helper function for AES block decryption
fn aes_decrypt_block(
    key_handle: BCRYPT_KEY_HANDLE,
    block: &[u8],
) -> Result<[u8; 16], ManticoreError> {
    #[allow(unsafe_code)]
    // SAFETY: Calls BCryptDecrypt with valid key handle and block pointers. Output buffer is sized for a 16-byte block.
    unsafe {
        let mut output = [0u8; 16];
        let mut cb_result = 0u32;

        let result = BCryptDecrypt(
            key_handle,
            Some(block),
            None,
            None, // No IV for ECB mode
            Some(&mut output),
            &mut cb_result,
            BCRYPT_FLAGS(0),
        );

        if !result.is_ok() {
            tracing::error!(
                "Windows CNG API: AES block decryption failed: 0x{:08x}",
                result.0
            );
            return Err(ManticoreError::AesDecryptError);
        }

        Ok(output)
    }
}

// Multiply by α in GF(2^128) - the primitive polynomial is x^128 + x^7 + x^2 + x + 1
fn gf128_mul_alpha(mut input: [u8; 16]) -> [u8; 16] {
    let msb = input[15] & 0x80; // Check most significant bit

    // Left shift by 1 bit
    for i in (1..16).rev() {
        input[i] = (input[i] << 1) | (input[i - 1] >> 7);
    }
    input[0] <<= 1;

    // If MSB was set, XOR with the reduction polynomial (0x87)
    if msb != 0 {
        input[0] ^= 0x87;
    }

    input
}
