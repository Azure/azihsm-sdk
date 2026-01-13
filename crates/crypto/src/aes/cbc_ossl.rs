// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based AES-CBC encryption/decryption implementation.
//!
//! This module provides AES cipher block chaining (CBC) mode operations using OpenSSL
//! as the underlying cryptographic backend. It supports both single-operation and
//! streaming encryption/decryption with optional PKCS#7 padding.
//!
//! # CBC Mode
//!
//! Cipher Block Chaining (CBC) mode encrypts blocks sequentially, with each plaintext
//! block XORed with the previous ciphertext block before encryption. This creates
//! dependency between blocks, making CBC mode unsuitable for parallel processing but
//! providing better security than ECB mode.
//!
//! # Security Considerations
//!
//! - **IV Requirements**: The initialization vector (IV) must be unpredictable and unique
//!   for each encryption operation with the same key
//! - **Padding Oracle Attacks**: Care must be taken when handling padding errors in decryption
//! - **Authentication**: CBC mode does not provide authentication; consider using AEAD modes
//!   like AES-GCM for new applications
//! - **IV Reuse**: Never reuse the same key-IV pair for different plaintexts

use openssl::symm::*;

use super::*;

/// OpenSSL AES-CBC encryption/decryption operation.
///
/// This structure configures an AES-CBC operation with padding mode and initialization
/// vector. It implements both single-operation and streaming encryption/decryption.
///
/// # Lifetime Parameters
///
/// * `'a` - Lifetime of the initialization vector reference
///
/// # Fields
///
/// The structure maintains:
/// - Padding configuration (PKCS#7 padding enabled/disabled)
/// - Initialization vector for CBC mode
///
/// # Thread Safety
///
/// This structure is not `Send` or `Sync` due to the borrowed IV. For concurrent
/// operations, create separate instances with their own IVs.
pub struct OsslAesCbcAlgo {
    /// Whether to use PKCS#7 padding for incomplete blocks
    pad: bool,

    /// Initialization vector for CBC mode (must be 16 bytes for AES)
    iv: Vec<u8>,
}

impl OsslAesCbcAlgo {
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

    /// Returns the appropriate OpenSSL cipher based on key size.
    ///
    /// This internal method selects the correct AES-CBC cipher variant (128, 192, or 256-bit)
    /// based on the provided key size.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Size of the key in bytes (16, 24, or 32)
    ///
    /// # Returns
    ///
    /// The corresponding OpenSSL `Cipher` for AES-CBC with the specified key size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn cipher(key_size: usize) -> Result<Cipher, CryptoError> {
        match key_size {
            16 => Ok(Cipher::aes_128_cbc()),
            24 => Ok(Cipher::aes_192_cbc()),
            32 => Ok(Cipher::aes_256_cbc()),
            _ => Err(CryptoError::AesInvalidKeySize),
        }
    }
}

/// Implements single-operation encryption for AES-CBC.
impl EncryptOp for OsslAesCbcAlgo {
    type Key = AesKey;

    /// Performs AES-CBC encryption in a single operation.
    ///
    /// This method processes the entire input data at once. For large data or streaming
    /// scenarios, consider using `encrypt_init` to create a streaming context.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    /// * `input` - Input plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The input size is invalid (not a multiple of block size when padding is disabled)
    /// - The IV size is incorrect (must be 16 bytes)
    /// - The underlying OpenSSL operation fails
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let mut count = 0;
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;
        if let Some(output) = output {
            let pad = self.pad();
            let iv = self.iv_mut();
            let mut crypter = Crypter::new(cipher, Mode::Encrypt, key_bytes, Some(iv))
                .map_err(|_| CryptoError::AesError)?;
            crypter.pad(pad);
            count += crypter
                .update(input, output)
                .map_err(|_| CryptoError::AesEncryptError)?;
            count += crypter
                .finalize(&mut output[count..])
                .map_err(|_| CryptoError::AesEncryptError)?;
            iv.copy_from_slice(&output[count - iv.len()..count]);
        } else {
            // The required output buffer size for OpenSSL's `update` is
            // `input.len() + block_size` regardless of whether padding is enabled.
            count = input.len() + cipher.block_size();
        }
        Ok(count)
    }
}

/// Implements streaming encryption for AES-CBC.
impl<'a> EncryptStreamingOp<'a> for OsslAesCbcAlgo {
    type Key = AesKey;
    type Context = OsslAesCbcEncryptContext;

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
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 16 bytes)
    /// - OpenSSL context initialization fails
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, super::CryptoError> {
        let key_bytes = key.bytes();
        let mut crypter = Crypter::new(
            Self::cipher(key_bytes.len())?,
            Mode::Encrypt,
            key_bytes,
            Some(&self.iv),
        )
        .map_err(|_| CryptoError::AesError)?;
        crypter.pad(self.pad);

        Ok(OsslAesCbcEncryptContext {
            algo: self,
            crypter,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-CBC encryption operations.
///
/// This structure maintains the state for a multi-step AES-CBC encryption operation.
/// It is created by `OsslAesCbc::encrypt_init` and processes data incrementally
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
/// - OpenSSL cipher context with key and IV
/// - Buffered partial blocks (data smaller than 16 bytes)
/// - Padding configuration from the parent operation
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesCbcEncryptContext {
    algo: OsslAesCbcAlgo,
    crypter: Crypter,
    block: AesBlock,
}

/// Implements streaming encryption operations for the AES-CBC encrypt context.
impl<'a> EncryptOpContext<'a> for OsslAesCbcEncryptContext {
    type Algo = OsslAesCbcAlgo;
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
    /// - The underlying OpenSSL update operation fails
    fn update(
        &mut self,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        if let Some(output) = output {
            let mut offset = 0;
            self.block.update(input, |data| {
                let count = self
                    .crypter
                    .update(data, &mut output[offset..])
                    .map_err(|_| CryptoError::AesEncryptError)?;
                offset += count;
                Ok(count)
            })
        } else {
            self.block.update_len(input)
        }
    }

    /// Finalizes the encryption/decryption operation.
    ///
    /// This method completes the operation by:
    /// - Processing any remaining buffered data
    /// - Applying padding (encryption) or validating padding (decryption)
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
    /// - Padding validation fails during decryption (invalid padding)
    /// - Input data size is not a multiple of block size (when padding is disabled)
    /// - The underlying OpenSSL finalization fails
    ///
    /// # Security
    ///
    /// For decryption, this method validates PKCS#7 padding. Invalid padding may
    /// indicate data corruption or tampering. Handle padding errors carefully to
    /// avoid padding oracle vulnerabilities.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, super::CryptoError> {
        if let Some(output) = output {
            self.block.r#final(|input| {
                let mut count = self
                    .crypter
                    .update(input, output)
                    .map_err(|_| CryptoError::AesEncryptError)?;
                count += self
                    .crypter
                    .finalize(&mut output[count..])
                    .map_err(|_| CryptoError::AesEncryptError)?;
                let iv_len = self.algo.iv.len();
                if count >= iv_len {
                    self.algo.iv.copy_from_slice(&output[count - iv_len..count]);
                }
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

/// Implements single-operation decryption for AES-CBC.
impl DecryptOp for OsslAesCbcAlgo {
    type Key = AesKey;

    /// Performs AES-CBC decryption in a single operation.
    ///
    /// This method processes the entire input data at once. For large data or streaming
    /// scenarios, consider using `decrypt_init` to create a streaming context.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES key (128, 192, or 256 bits)
    /// * `input` - Input ciphertext data to decrypt
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size
    /// if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The input size is invalid (not a multiple of block size when padding is disabled)
    /// - The IV size is incorrect (must be 16 bytes)
    /// - Padding validation fails
    /// - The underlying OpenSSL operation fails
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        let mut count = 0;
        let key_bytes = key.bytes();
        let cipher = Self::cipher(key_bytes.len())?;
        if let Some(output) = output {
            let pad = self.pad();
            let iv = self.iv_mut();
            let mut crypter = Crypter::new(cipher, Mode::Decrypt, key_bytes, Some(iv))
                .map_err(|_| CryptoError::AesError)?;
            crypter.pad(pad);
            count += crypter
                .update(input, output)
                .map_err(|_| CryptoError::AesDecryptError)?;
            count += crypter
                .finalize(&mut output[count..])
                .map_err(|_| CryptoError::AesDecryptError)?;
            iv.copy_from_slice(&input[input.len() - iv.len()..]);
        } else {
            count = input.len() + cipher.block_size();
        }
        Ok(count)
    }
}

/// Implements streaming decryption for AES-CBC.
impl<'a> DecryptStreamingOp<'a> for OsslAesCbcAlgo {
    type Key = AesKey;
    type Context = OsslAesCbcDecryptContext;

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
    /// - The key size is invalid
    /// - The IV size is incorrect (must be 16 bytes)
    /// - OpenSSL context initialization fails
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, super::CryptoError> {
        let key_bytes = key.bytes();
        let mut crypter = Crypter::new(
            Self::cipher(key_bytes.len())?,
            Mode::Decrypt,
            key_bytes,
            Some(&self.iv),
        )
        .map_err(|_| CryptoError::AesError)?;
        crypter.pad(self.pad);

        Ok(OsslAesCbcDecryptContext {
            algo: self,
            crypter,
            block: AesBlock::default(),
        })
    }
}

/// Streaming context for AES-CBC decryption operations.
///
/// This structure maintains the state for a multi-step AES-CBC decryption operation.
/// It is created by `OsslAesCbc::decrypt_init` and processes data incrementally
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
/// - OpenSSL cipher context with key and IV
/// - Buffered partial blocks (data smaller than 16 bytes)
/// - Padding configuration from the parent operation
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct OsslAesCbcDecryptContext {
    algo: OsslAesCbcAlgo,
    crypter: Crypter,
    block: AesBlock,
}

/// Implements streaming decryption operations for the AES-CBC decrypt context.
impl<'a> DecryptOpContext<'a> for OsslAesCbcDecryptContext {
    /// Algo associated with this context.
    type Algo = OsslAesCbcAlgo;

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
    /// - The underlying OpenSSL update operation fails
    fn update(
        &mut self,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        if let Some(output) = output {
            let mut offset = 0;
            self.block.update(input, |data| {
                let count = self
                    .crypter
                    .update(data, &mut output[offset..])
                    .map_err(|_| CryptoError::AesDecryptError)?;
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
    /// - Validating PKCS#7 padding
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
    /// - Padding validation fails during decryption (invalid padding)
    /// - Input data size is not a multiple of block size (when padding is disabled)
    /// - The underlying OpenSSL finalization fails
    ///
    /// # Security
    ///
    /// For decryption, this method validates PKCS#7 padding. Invalid padding may
    /// indicate data corruption or tampering. Handle padding errors carefully to
    /// avoid padding oracle vulnerabilities.
    fn finish(&mut self, output: Option<&mut [u8]>) -> Result<usize, super::CryptoError> {
        if let Some(output) = output {
            self.block.r#final(|input| {
                let mut count = self
                    .crypter
                    .update(input, output)
                    .map_err(|_| CryptoError::AesDecryptError)?;
                count += self
                    .crypter
                    .finalize(&mut output[count..])
                    .map_err(|_| CryptoError::AesDecryptError)?;
                // Note: IV is updated in the context but not propagated back to the caller
                // For proper IV chaining in streaming mode, the IV should be the last block of ciphertext
                let iv_len = self.algo.iv.len();
                if input.len() >= iv_len {
                    self.algo.iv.copy_from_slice(&input[input.len() - iv_len..]);
                }
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
