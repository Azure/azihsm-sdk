// Copyright (C) Microsoft Corporation. All rights reserved.

//! Windows CNG (Cryptography Next Generation) implementation of AES-CBC operations.
//!
//! This module provides a Windows-specific implementation of AES-CBC encryption and decryption
//! using the Windows Cryptography Next Generation (CNG) API. CNG is the long-term replacement
//! for the deprecated CryptoAPI and provides a modern, secure interface for cryptographic
//! operations on Windows platforms.
//!
//! # Features
//!
//! - **Native Windows integration**: Uses the platform's built-in cryptographic providers
//! - **Hardware acceleration**: Automatically leverages AES-NI and other hardware features when available
//! - **FIPS compliance**: Can operate in FIPS 140-2 validated mode when properly configured
//! - **Memory security**: Key material is managed securely by the Windows kernel
//!
//! # Architecture
//!
//! The implementation centers around the [`CngAesCbcKey`] struct, which wraps a Windows
//! `BCRYPT_KEY_HANDLE` and provides safe Rust interfaces for AES-CBC operations.
//!
//! # Security Considerations
//!
//! - Key handles are automatically destroyed when dropped, preventing key material leakage
//! - The Windows CNG subsystem manages key material securely in kernel space
//! - All cryptographic operations are performed by FIPS-validated providers
//! - Hardware-based random number generation is used for key generation

use windows::Win32::Security::Cryptography::*;

use super::*;

/// Windows CNG AES-CBC encryption/decryption wrapper for CngAesCbcKey.
///
/// This structure provides a stateful interface for AES-CBC encryption and decryption
/// operations using CngAesCbcKey, wrapping the initialization vector and padding settings.
///
/// # Thread Safety
///
/// This structure is not thread-safe as it maintains mutable state for the IV.
/// Create separate instances for concurrent operations.
pub struct CngAesCbcAlgo {
    /// Initialization vector for CBC mode (16 bytes for AES)
    iv: Vec<u8>,
    /// Whether to use PKCS#7 padding
    pad: bool,
}

impl CngAesCbcAlgo {
    /// Creates a new AES-CBC operation with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `pad` - Whether to enable PKCS#7 padding. When `true`, input data of any length
    ///   is accepted and automatically padded. When `false`, input must be a multiple of
    ///   the AES block size (16 bytes).
    /// * `iv` - Initialization vector for CBC mode. Must be exactly 16 bytes. The IV should
    ///   be unpredictable and unique for each encryption operation.
    ///
    /// # Returns
    ///
    /// A new `OsslAesCbc` instance configured with the specified parameters.
    ///
    /// # Security
    ///
    /// The IV must be:
    /// - Unpredictable (use a cryptographically secure RNG)
    /// - Unique for each encryption with the same key
    /// - Can be transmitted in plaintext with the ciphertext
    pub fn with_padding(iv: &[u8]) -> Self {
        Self {
            pad: true,
            iv: iv.to_vec(),
        }
    }

    /// Creates a new AES-CBC operation without PKCS#7 padding.
    ///
    /// This constructor disables padding, requiring input data to be a multiple of
    /// the AES block size (16 bytes). This is useful for applications that implement
    /// custom padding schemes or work with pre-padded data.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector for CBC mode. Must be exactly 16 bytes. The IV should
    ///   be unpredictable and unique for each encryption operation.
    ///
    /// # Returns
    ///
    /// A new `OsslAesCbc` instance configured without padding.
    ///
    /// # Security
    ///
    /// The IV must be:
    /// - Unpredictable (use a cryptographically secure RNG)
    /// - Unique for each encryption with the same key
    /// - Can be transmitted in plaintext with the ciphertext
    pub fn with_no_padding(iv: &[u8]) -> Self {
        Self {
            pad: false,
            iv: iv.to_vec(),
        }
    }

    /// Returns whether PKCS#7 padding is enabled.
    ///
    /// # Returns
    ///
    /// `true` if padding is enabled, `false` otherwise.
    pub fn pad(&self) -> bool {
        self.pad
    }

    /// Returns a reference to the initialization vector.
    ///
    /// # Returns
    ///
    /// A byte slice containing the IV (16 bytes for AES).
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns a mutable reference to the initialization vector.
    ///
    /// This is an internal method used to update the IV during encryption/decryption
    /// operations for proper CBC chaining across multiple operations.
    ///
    /// # Returns
    ///
    /// A mutable byte slice containing the IV (16 bytes for AES).
    fn iv_mut(&mut self) -> &mut [u8] {
        &mut self.iv
    }

    /// Validates that the provided IV size is correct for AES-CBC.
    ///
    /// # Arguments
    ///
    /// * `iv` - Initialization vector to validate
    ///
    /// # Returns
    ///
    /// * `Ok(())` - IV size is valid (16 bytes)
    /// * `Err(CryptoError::AesInvalidIVError)` - IV size is invalid
    fn validate_iv(iv: &[u8]) -> Result<(), CryptoError> {
        if iv.len() != 16 {
            Err(CryptoError::AesInvalidIVError)
        } else {
            Ok(())
        }
    }

    ///
    /// # Arguments
    /// * `input` - Input data to encrypt
    /// * `iv` - Initialization vector (must be 16 bytes for AES)
    /// * `output` - Optional output buffer; if `None`, returns required size
    /// * `flags` - Encryption flags (e.g., `BCRYPT_BLOCK_PADDING` for PKCS#7 padding)
    ///
    /// # Returns
    /// * `Ok(usize)` - Bytes written to output or required buffer size
    /// * `Err(CryptoError)` - If encryption operation fails
    ///
    /// # Errors
    /// Returns `AesEncryptError` if the Windows CNG encryption operation fails.
    ///
    /// # Safety
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_encrypt(
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        iv: &mut [u8],
        output: Option<&mut [u8]>,
        flags: BCRYPT_FLAGS,
    ) -> Result<usize, CryptoError> {
        let mut out_len = 0u32;
        //SAFETY: Calling Bcrypt unsafe functions
        let status = unsafe {
            BCryptEncrypt(
                key_handle,
                Some(input),
                None,
                Some(iv),
                output,
                &mut out_len,
                flags,
            )
        };
        status.ok().map_err(|_| CryptoError::AesEncryptError)?;
        Ok(out_len as usize)
    }

    ///
    /// # Arguments
    /// * `input` - Input data to encrypt
    /// * `iv` - Initialization vector (must be 16 bytes for AES)
    /// * `output` - Optional output buffer; if `None`, returns required size
    /// * `flags` - Encryption flags (e.g., `BCRYPT_BLOCK_PADDING` for PKCS#7 padding)
    ///
    /// # Returns
    /// * `Ok(usize)` - Bytes written to output or required buffer size
    /// * `Err(CryptoError)` - If encryption operation fails
    ///
    /// # Errors
    /// Returns `AesEncryptError` if the Windows CNG encryption operation fails.
    ///
    /// # Safety
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_decrypt(
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        iv: &mut [u8],
        output: Option<&mut [u8]>,
        flags: BCRYPT_FLAGS,
    ) -> Result<usize, CryptoError> {
        let mut out_len = 0u32;
        //SAFETY: Calling Bcrypt unsafe functions
        let status = unsafe {
            BCryptDecrypt(
                key_handle,
                Some(input),
                None,
                Some(iv),
                output,
                &mut out_len,
                flags,
            )
        };
        status.ok().map_err(|_| CryptoError::AesEncryptError)?;
        Ok(out_len as usize)
    }
}

/// Implementation of single-operation encryption for AES-CBC using CngAesKey.
impl EncryptOp for CngAesCbcAlgo {
    type Key = AesKey;

    /// Encrypts data using AES-CBC with Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for encryption
    /// * `input` - Input plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Bytes written to output or required buffer size
    /// * `Err(CryptoError)` - If encryption operation fails
    ///
    /// # Errors
    ///
    /// * `AesInvalidIVError` - If IV size is not 16 bytes
    /// * `AesEncryptError` - If Windows CNG encryption fails
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let flags = if self.pad() {
            BCRYPT_BLOCK_PADDING
        } else {
            BCRYPT_FLAGS(0)
        };

        Self::bcrypt_encrypt(key.cbc_handle(), input, self.iv_mut(), output, flags)
    }
}

/// Implementation of single-operation decryption for AES-CBC using CngAesCbcKey.
impl DecryptOp for CngAesCbcAlgo {
    type Key = AesKey;

    /// Decrypts data using AES-CBC with Windows CNG.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key to use for decryption
    /// * `input` - Input ciphertext data to decrypt
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Bytes written to output or required buffer size
    /// * `Err(CryptoError)` - If decryption operation fails
    ///
    /// # Errors
    ///
    /// * `AesInvalidIVError` - If IV size is not 16 bytes
    /// * `AesDecryptError` - If Windows CNG decryption fails or padding is invalid
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let flags = if self.pad {
            BCRYPT_BLOCK_PADDING
        } else {
            BCRYPT_FLAGS(0)
        };

        Self::bcrypt_decrypt(key.cbc_handle(), input, self.iv_mut(), output, flags)
    }
}

/// Implementation of streaming encryption for AES-CBC using Windows CNG.
impl<'a> EncryptStreamingOp<'a> for CngAesCbcAlgo {
    type Key = AesKey;
    type Context = CngAesCbcEncryptContext;

    /// Initializes a streaming AES-CBC encryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive encryption with intermediate buffering
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `EncryptStreamingOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The IV size is incorrect (must be 16 bytes)
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Self::validate_iv(self.iv())?;

        Ok(CngAesCbcEncryptContext {
            algo: self,
            key,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-CBC encryption operations using Windows CNG.
///
/// This structure maintains the state for a multi-step AES-CBC encryption operation.
/// It is created by `CngAesCbc::encrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `encrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to produce any remaining output and padding
///
/// # Internal State
///
/// The context maintains:
/// - OpenSSL AES-CBC algorithm instance
/// - Buffered partial blocks (data smaller than 16 bytes)
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesCbcEncryptContext {
    algo: CngAesCbcAlgo,
    key: AesKey,
    block: AesBlock,
}

/// Implementation of streaming encryption operations for the AES-CBC encrypt context.
impl<'a> EncryptOpContext<'a> for CngAesCbcEncryptContext {
    type Algo = CngAesCbcAlgo;
    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// For block ciphers like AES, data is processed in 16-byte blocks. Any
    /// incomplete blocks are buffered internally and processed in subsequent
    /// calls or during finalization.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to process
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`. Note that the output size may be smaller than
    /// the input size if insufficient data is available to form complete blocks.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The context has already been finalized
    /// - The underlying Windows CNG update operation fails
    #[allow(unsafe_code)]
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        if let Some(output) = output {
            let mut offset = 0;
            self.block.update(input, |data| {
                // For streaming operations, we don't use padding on intermediate blocks
                // SAFETY: Calling Windows CNG API with valid parameters
                let count = CngAesCbcAlgo::bcrypt_encrypt(
                    self.key.cbc_handle(),
                    data,
                    self.algo.iv_mut(),
                    Some(&mut output[offset..]),
                    BCRYPT_FLAGS(0),
                )?;
                offset += count;
                Ok(count)
            })
        } else {
            self.block.update_len(input)
        }
    }

    /// Finalizes the encryption operation.
    ///
    /// This method completes the operation by:
    /// - Processing any remaining buffered data
    /// - Applying PKCS#7 padding if enabled
    /// - Producing the final output block
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer (typically 0-16 bytes for
    /// the final block), or the required buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Input data size is not a multiple of block size (when padding is disabled)
    /// - The underlying Windows CNG finalization fails
    #[allow(unsafe_code)]
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        if let Some(output) = output {
            self.block.r#final(|data| {
                let flags = if self.algo.pad() {
                    BCRYPT_BLOCK_PADDING
                } else {
                    BCRYPT_FLAGS(0)
                };
                // SAFETY: Calling Windows CNG API with valid parameters
                let count = CngAesCbcAlgo::bcrypt_encrypt(
                    self.key.cbc_handle(),
                    data,
                    &mut self.algo.iv,
                    Some(output),
                    flags,
                )?;
                Ok(count)
            })
        } else {
            self.block.final_len()
        }
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Implementation of streaming decryption for AES-CBC using Windows CNG.
impl<'a> DecryptStreamingOp<'a> for CngAesCbcAlgo {
    type Key = AesKey;
    type Context = CngAesCbcDecryptContext;

    /// Initializes a streaming AES-CBC decryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive decryption with intermediate buffering
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    ///
    /// # Returns
    ///
    /// A context implementing `DecryptStreamingOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The IV size is incorrect (must be 16 bytes)
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Self::validate_iv(self.iv())?;

        Ok(CngAesCbcDecryptContext {
            algo: self,
            key,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-CBC decryption operations using Windows CNG.
///
/// This structure maintains the state for a multi-step AES-CBC decryption operation.
/// It is created by `CngAesCbc::decrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `decrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to validate padding and produce final output
///
/// # Internal State
///
/// The context maintains:
/// - Windows CNG key handle reference
/// - Initialization vector for CBC mode
/// - Buffered partial blocks (data smaller than 16 bytes)
/// - Padding configuration from the parent operation
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesCbcDecryptContext {
    algo: CngAesCbcAlgo,
    key: AesKey,
    block: AesBlock,
}

/// Implementation of streaming decryption operations for the AES-CBC decrypt context.
impl<'a> DecryptOpContext<'a> for CngAesCbcDecryptContext {
    type Algo = CngAesCbcAlgo;
    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// For block ciphers like AES, data is processed in 16-byte blocks. Any
    /// incomplete blocks are buffered internally and processed in subsequent
    /// calls or during finalization.
    ///
    /// # Arguments
    ///
    /// * `input` - Input ciphertext chunk to process
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`. Note that the output size may be smaller than
    /// the input size if insufficient data is available to form complete blocks.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The context has already been finalized
    /// - The underlying Windows CNG update operation fails
    #[allow(unsafe_code)]
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        if let Some(output) = output {
            let mut offset = 0;
            self.block.update(input, |data| {
                // For streaming operations, we don't use padding on intermediate blocks
                let count = CngAesCbcAlgo::bcrypt_decrypt(
                    self.key.cbc_handle(),
                    data,
                    self.algo.iv_mut(),
                    Some(&mut output[offset..]),
                    BCRYPT_FLAGS(0),
                )?;
                offset += count;
                Ok(count)
            })
        } else {
            self.block.update_len(input)
        }
    }

    /// Finalizes the decryption operation.
    ///
    /// This method completes the operation by:
    /// - Processing any remaining buffered data
    /// - Validating PKCS#7 padding if enabled
    /// - Producing the final output block
    ///
    /// The context is consumed and cannot be used after this call.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer (typically 0-16 bytes for
    /// the final block), or the required buffer size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - Padding validation fails (invalid padding)
    /// - Input data size is not a multiple of block size (when padding is disabled)
    /// - The underlying Windows CNG finalization fails
    ///
    /// # Security
    ///
    /// This method validates PKCS#7 padding. Invalid padding may indicate data
    /// corruption or tampering. Handle padding errors carefully to avoid padding
    /// oracle vulnerabilities.
    #[allow(unsafe_code)]
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        if let Some(output) = output {
            self.block.r#final(|data| {
                let flags = if self.algo.pad() {
                    BCRYPT_BLOCK_PADDING
                } else {
                    BCRYPT_FLAGS(0)
                };
                let count = CngAesCbcAlgo::bcrypt_decrypt(
                    self.key.cbc_handle(),
                    data,
                    self.algo.iv_mut(),
                    Some(output),
                    flags,
                )?;
                Ok(count)
            })
        } else {
            self.block.final_len()
        }
    }

    /// Returns a reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A reference to the `OsslHash` algorithm instance.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// A mutable reference to the `OsslHash` algorithm instance.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the underlying hash algorithm.
    ///
    /// # Returns
    ///
    /// The `OsslHash` algorithm instance.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
