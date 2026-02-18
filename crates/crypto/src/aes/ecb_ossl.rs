// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSSL-based AES-ECB encryption/decryption implementation.
//!
//! This module provides AES-ECB (Electronic Codebook) mode encryption using OpenSSL.
//! ECB is a block cipher mode that encrypts each block of plaintext independently.
//!
//! # Security Warning
//!
//! ECB mode is NOT recommended for most cryptographic applications because identical
//! plaintext blocks produce identical ciphertext blocks, which can leak information
//! about the plaintext structure. Consider using CBC, GCM, or other authenticated
//! encryption modes instead.
//!
//! # Block Size Requirement
//!
//! Input data must be a multiple of the AES block size (16 bytes). No padding is applied.

use openssl::cipher::*;
use openssl::cipher_ctx::*;

use super::*;

/// OpenSSL AES-ECB encryption/decryption operation.
///
/// This structure provides AES-ECB mode encryption and decryption using OpenSSL.
/// It supports AES with 128, 192, and 256-bit keys.
///
/// # Security Considerations
///
/// ECB mode encrypts each block independently, which means:
/// - Identical plaintext blocks produce identical ciphertext blocks
/// - Patterns in the plaintext are preserved in the ciphertext
/// - No protection against block reordering or replay attacks
///
/// Use ECB mode only when:
/// - Processing random data with no patterns
/// - Encrypting single blocks
/// - Implementing higher-level protocols that handle security concerns
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync`.

#[derive(Default)]
pub struct OsslAesEcbAlgo;

impl OsslAesEcbAlgo {
    /// Returns the appropriate OpenSSL cipher based on key size.
    ///
    /// This internal method maps key sizes to their corresponding AES-ECB cipher variants.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Size of the key in bytes (16 for AES-128, 24 for AES-192, 32 for AES-256)
    ///
    /// # Returns
    ///
    /// The corresponding OpenSSL `Cipher` for AES-ECB with the specified key size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn cipher(key_size: usize) -> Result<&'static CipherRef, CryptoError> {
        match key_size {
            16 => Ok(Cipher::aes_128_ecb()),
            24 => Ok(Cipher::aes_192_ecb()),
            32 => Ok(Cipher::aes_256_ecb()),
            _ => Err(CryptoError::AesInvalidKeySize),
        }
    }
}

impl EncryptOp for OsslAesEcbAlgo {
    type Key = AesKey;

    /// Performs AES-ECB encryption in a single operation.
    ///
    /// Encrypts the input data using AES-ECB mode. The input must be a multiple of
    /// the AES block size (16 bytes). No padding is applied.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (16, 24, or 32 bytes for AES-128/192/256)
    /// * `input` - Input plaintext data to encrypt (must be multiple of 16 bytes)
    /// * `output` - Optional output buffer for ciphertext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If encryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesInvalidInputSize` - Input length is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesError` - Failed to initialize OpenSSL crypter
    /// - `CryptoError::AesEncryptError` - Encryption operation failed
    #[allow(unsafe_code)]
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;

        if !input.len().is_multiple_of(cipher.block_size()) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let len = input.len() + cipher.block_size();
        let count = if let Some(output) = output {
            // Validate output buffer size
            if output.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesEncryptError)?;
            ctx.set_padding(false);
            ctx.encrypt_init(Some(cipher), Some(key_bytes), None)
                .map_err(|_| CryptoError::AesEncryptError)?;
            let mut count = ctx
                .cipher_update(input, Some(output))
                .map_err(|_| CryptoError::AesEncryptError)?;
            count += ctx
                .cipher_final(&mut output[count..])
                .map_err(|_| CryptoError::AesEncryptError)?;
            debug_assert!(count == input.len());
            count
        } else {
            len
        };

        Ok(count)
    }
}

impl DecryptOp for OsslAesEcbAlgo {
    type Key = AesKey;

    /// Performs AES-ECB decryption in a single operation.
    ///
    /// Decrypts the input ciphertext using AES-ECB mode. The input must be a multiple of
    /// the AES block size (16 bytes). No padding is applied.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (16, 24, or 32 bytes for AES-128/192/256)
    /// * `input` - Input ciphertext data to decrypt (must be multiple of 16 bytes)
    /// * `output` - Optional output buffer for plaintext. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If decryption fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidKeySize` - Key size is not 16, 24, or 32 bytes
    /// - `CryptoError::AesInvalidInputSize` - Input length is not a multiple of 16 bytes
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesError` - Failed to initialize OpenSSL crypter
    /// - `CryptoError::AesDecryptError` - Decryption operation failed
    #[allow(unsafe_code)]
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;

        if !input.len().is_multiple_of(cipher.block_size()) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let len = input.len() + cipher.block_size();

        let count = if let Some(output) = output {
            // Validate output buffer size
            if output.len() < len {
                return Err(CryptoError::AesBufferTooSmall);
            }

            let mut ctx = CipherCtx::new().map_err(|_| CryptoError::AesDecryptError)?;
            ctx.decrypt_init(Some(cipher), Some(key_bytes), None)
                .map_err(|_| CryptoError::AesDecryptError)?;
            ctx.set_padding(false);
            let mut count = ctx
                .cipher_update(input, Some(output))
                .map_err(|_| CryptoError::AesDecryptError)?;
            count += ctx
                .cipher_final(&mut output[count..])
                .map_err(|_| CryptoError::AesDecryptError)?;
            debug_assert!(count == input.len());
            count
        } else {
            len
        };

        Ok(count)
    }
}
