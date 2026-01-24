// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES-GCM encryption and decryption operations.
//!
//! This module provides AES-GCM (Galois/Counter Mode) encryption and
//! decryption operations for HSM AES-GCM keys. GCM provides both
//! confidentiality and authenticity through an authentication tag.
//!
//! The implementation supports:
//! - **Single-shot** operations via [`HsmEncryptOp`] and [`HsmDecryptOp`]
//! - **Streaming** operations via [`HsmEncryptStreamingOp`] and [`HsmDecryptStreamingOp`]
//!
//! ## Authentication
//!
//! GCM is an authenticated encryption mode. Encryption produces a 16-byte
//! authentication tag that must be provided during decryption. If the tag
//! verification fails, decryption returns an error.
//!
//! ## Additional Authenticated Data (AAD)
//!
//! Optional AAD can be provided during encryption and decryption. AAD is
//! authenticated but not encrypted, and must match during decryption.

use super::*;

/// Size of the GCM initialization vector in bytes.
const GCM_IV_SIZE: usize = 12;

/// Size of the GCM authentication tag in bytes.
const GCM_TAG_SIZE: usize = 16;

/// An algorithm implementation for AES-GCM encryption and decryption.
///
/// This struct provides both single-shot and streaming encryption and decryption
/// operations using the AES algorithm in GCM (Galois/Counter Mode). It implements
/// the [`HsmEncryptOp`], [`HsmEncryptStreamingOp`], [`HsmDecryptOp`], and
/// [`HsmDecryptStreamingOp`] traits for HSM operations.
///
/// ## Usage Note
///
/// For encryption, the tag is produced as output and can be retrieved via
/// [`HsmAesGcmAlgo::tag`] after the operation completes.
///
/// For decryption, the tag must be provided when creating the algorithm instance.
pub struct HsmAesGcmAlgo {
    /// The initialization vector (12 bytes).
    iv: [u8; GCM_IV_SIZE],

    /// Optional additional authenticated data.
    aad: Option<Vec<u8>>,

    /// The authentication tag (16 bytes).
    /// For encryption: set after operation completes.
    /// For decryption: must be provided before operation.
    tag: Option<[u8; GCM_TAG_SIZE]>,
}

impl HsmAesGcmAlgo {
    /// Creates a new AES-GCM algorithm instance for encryption.
    ///
    /// The authentication tag will be generated during encryption and can be
    /// retrieved via [`HsmAesGcmAlgo::tag`] after the operation completes.
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector (must be exactly 12 bytes)
    /// * `aad` - Optional additional authenticated data
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - A configured AES-GCM algorithm instance for encryption
    /// * `Err(HsmError::InvalidArgument)` - If the IV is not exactly 12 bytes
    pub fn new_for_encryption(iv: Vec<u8>, aad: Option<Vec<u8>>) -> HsmResult<Self> {
        if iv.len() != GCM_IV_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        let mut iv_arr = [0u8; GCM_IV_SIZE];
        iv_arr.copy_from_slice(&iv);
        Ok(Self {
            iv: iv_arr,
            aad,
            tag: None,
        })
    }

    /// Creates a new AES-GCM algorithm instance for decryption.
    ///
    /// The authentication tag must be provided for verification during decryption.
    ///
    /// # Arguments
    ///
    /// * `iv` - The initialization vector (must be exactly 12 bytes)
    /// * `tag` - The authentication tag (must be exactly 16 bytes)
    /// * `aad` - Optional additional authenticated data
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - A configured AES-GCM algorithm instance for decryption
    /// * `Err(HsmError::InvalidArgument)` - If the IV or tag size is incorrect
    pub fn new_for_decryption(iv: Vec<u8>, tag: Vec<u8>, aad: Option<Vec<u8>>) -> HsmResult<Self> {
        if iv.len() != GCM_IV_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        if tag.len() != GCM_TAG_SIZE {
            return Err(HsmError::InvalidArgument);
        }
        let mut iv_arr = [0u8; GCM_IV_SIZE];
        iv_arr.copy_from_slice(&iv);
        let mut tag_arr = [0u8; GCM_TAG_SIZE];
        tag_arr.copy_from_slice(&tag);
        Ok(Self {
            iv: iv_arr,
            aad,
            tag: Some(tag_arr),
        })
    }

    /// Returns a reference to the initialization vector.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Returns the authentication tag.
    ///
    /// For encryption: returns the tag after the operation completes.
    /// For decryption: returns the tag that was provided for verification.
    ///
    /// # Returns
    ///
    /// * `Some(&[u8; 16])` - The authentication tag
    /// * `None` - If the tag has not been set (encryption not yet performed)
    pub fn tag(&self) -> Option<&[u8; GCM_TAG_SIZE]> {
        self.tag.as_ref()
    }

    /// Returns a copy of the AAD if present.
    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }
}

impl HsmEncryptOp for HsmAesGcmAlgo {
    type Key = HsmAesGcmKey;
    type Error = HsmError;

    /// Encrypts plaintext using AES-GCM mode.
    ///
    /// This method performs single-shot encryption of data using AES-GCM mode.
    /// After encryption, the authentication tag can be retrieved via [`HsmAesGcmAlgo::tag`].
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-GCM key to use for encryption
    /// * `plaintext` - The data to encrypt
    /// * `ciphertext` - Optional buffer to write encrypted data to. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written to ciphertext, or required buffer size if `ciphertext` is `None`
    /// * `Err(HsmError::InvalidKey)` - If the key cannot be used for encryption
    /// * `Err(HsmError::BufferTooSmall)` - If the provided ciphertext buffer is too small
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check if key can encrypt
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // GCM ciphertext is same length as plaintext
        let expected_len = plaintext.len();

        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };

        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let result = ddi::aes_gcm_encrypt(key, self.iv, self.aad.clone(), plaintext, ciphertext)?;

        // Store the tag and IV from the result
        self.tag = Some(result.tag);
        self.iv = result.iv;

        Ok(result.bytes_written)
    }
}

impl HsmDecryptOp for HsmAesGcmAlgo {
    type Key = HsmAesGcmKey;
    type Error = HsmError;

    /// Decrypts ciphertext using AES-GCM mode.
    ///
    /// This method performs single-shot decryption of data using AES-GCM mode.
    /// The authentication tag must have been provided when creating the algorithm
    /// instance via [`HsmAesGcmAlgo::new_for_decryption`].
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-GCM key to use for decryption
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `plaintext` - Optional buffer to write decrypted data to. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The number of bytes written to plaintext
    /// * `Err(HsmError::InvalidKey)` - If the key cannot be used for decryption
    /// * `Err(HsmError::InvalidArgument)` - If the tag was not provided
    /// * `Err(HsmError::BufferTooSmall)` - If the provided plaintext buffer is too small
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check if key can decrypt
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // Tag must be provided for decryption
        let tag = self.tag.ok_or(HsmError::InvalidArgument)?;

        // GCM plaintext is same length as ciphertext
        let expected_len = ciphertext.len();

        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };

        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        ddi::aes_gcm_decrypt(key, self.iv, tag, self.aad.clone(), ciphertext, plaintext)
    }
}

/// Maximum buffer size supported by DDI for AES-GCM operations.
/// This is used for streaming operations to buffer data before sending to the device.
const AES_GCM_MAX_BUFFER_SIZE: usize = 4096;

/// A context for streaming AES-GCM encryption operations.
///
/// This struct maintains the state of an ongoing AES-GCM encryption operation,
/// allowing data to be encrypted incrementally through multiple calls.
///
/// Note: Since GCM is message-based and not block-chaining, the streaming API
/// buffers data up to the maximum DDI buffer size before processing.
pub struct HsmAesGcmEncryptContext {
    /// The AES-GCM algorithm configuration.
    algo: HsmAesGcmAlgo,

    /// The AES-GCM key being used for encryption.
    key: HsmAesGcmKey,

    /// Internal buffer for accumulating data.
    buffer: Vec<u8>,
}

impl HsmEncryptStreamingOp for HsmAesGcmAlgo {
    type Key = HsmAesGcmKey;
    type Error = HsmError;
    type Context = HsmAesGcmEncryptContext;

    /// Initializes a streaming AES-GCM encryption operation.
    ///
    /// Creates an encryption context that allows data to be encrypted incrementally
    /// through multiple calls to `update` and a final call to `finish`.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-GCM key to use for encryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesGcmEncryptContext)` - An initialized encryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot be used for encryption
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // Check if key can encrypt
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        Ok(HsmAesGcmEncryptContext {
            algo: self,
            key,
            buffer: Vec::with_capacity(AES_GCM_MAX_BUFFER_SIZE),
        })
    }
}

impl HsmEncryptContext for HsmAesGcmEncryptContext {
    type Algo = HsmAesGcmAlgo;

    /// Encrypts a chunk of plaintext in the streaming operation.
    ///
    /// For AES-GCM, data is buffered until `finish` is called, since GCM
    /// is message-based and the tag is computed over the entire message.
    /// When the buffer reaches the maximum size, it is encrypted and output.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext data to encrypt
    /// * `ciphertext` - Optional buffer for encrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written (may be 0 if data is buffered)
    fn update(
        &mut self,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        // Calculate how much we can buffer and how much needs to be processed
        let space_in_buffer = AES_GCM_MAX_BUFFER_SIZE.saturating_sub(self.buffer.len());
        let to_buffer = plaintext.len().min(space_in_buffer);
        let remaining = &plaintext[to_buffer..];

        // If buffer won't overflow and no ciphertext buffer is provided, just calculate size
        if self.buffer.len() + plaintext.len() <= AES_GCM_MAX_BUFFER_SIZE {
            // All data fits in buffer, no output yet
            if ciphertext.is_none() {
                return Ok(0);
            }
            self.buffer.extend_from_slice(plaintext);
            return Ok(0);
        }

        // Buffer will overflow, need to encrypt current buffer + overflow
        let total_to_encrypt = self.buffer.len() + to_buffer;

        // For size query
        let Some(ciphertext) = ciphertext else {
            // Return size of what would be encrypted
            return Ok(total_to_encrypt);
        };

        if ciphertext.len() < total_to_encrypt {
            return Err(HsmError::BufferTooSmall);
        }

        // Add data to buffer
        self.buffer.extend_from_slice(&plaintext[..to_buffer]);

        // Encrypt the full buffer
        let result = ddi::aes_gcm_encrypt(
            &self.key,
            self.algo.iv,
            self.algo.aad.clone(),
            &self.buffer,
            ciphertext,
        )?;

        // Update IV and tag
        self.algo.iv = result.iv;
        self.algo.tag = Some(result.tag);

        // Clear buffer and add remaining data
        self.buffer.clear();
        self.buffer.extend_from_slice(remaining);

        Ok(result.bytes_written)
    }

    /// Finalizes the streaming encryption operation and produces final ciphertext.
    ///
    /// Encrypts any remaining buffered data and produces the authentication tag.
    /// The tag can be retrieved via [`HsmAesGcmAlgo::tag`] on the algorithm after
    /// calling [`HsmEncryptContext::into_algo`].
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Optional buffer for final encrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written
    fn finish(
        &mut self,
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        if self.buffer.is_empty() {
            return Ok(0);
        }

        let expected_len = self.buffer.len();

        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };

        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let result = ddi::aes_gcm_encrypt(
            &self.key,
            self.algo.iv,
            self.algo.aad.clone(),
            &self.buffer,
            ciphertext,
        )?;

        // Store the tag
        self.algo.tag = Some(result.tag);
        self.algo.iv = result.iv;
        self.buffer.clear();

        Ok(result.bytes_written)
    }

    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// A context for streaming AES-GCM decryption operations.
///
/// This struct maintains the state of an ongoing AES-GCM decryption operation,
/// allowing data to be decrypted incrementally through multiple calls.
///
/// Note: Since GCM is message-based and requires tag verification, the streaming
/// API buffers data up to the maximum DDI buffer size before processing.
pub struct HsmAesGcmDecryptContext {
    /// The AES-GCM algorithm configuration.
    algo: HsmAesGcmAlgo,

    /// The AES-GCM key being used for decryption.
    key: HsmAesGcmKey,

    /// Internal buffer for accumulating data.
    buffer: Vec<u8>,
}

impl HsmDecryptStreamingOp for HsmAesGcmAlgo {
    type Key = HsmAesGcmKey;
    type Error = HsmError;
    type Context = HsmAesGcmDecryptContext;

    /// Initializes a streaming AES-GCM decryption operation.
    ///
    /// Creates a decryption context that allows data to be decrypted incrementally
    /// through multiple calls to `update` and a final call to `finish`.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-GCM key to use for decryption
    ///
    /// # Returns
    ///
    /// * `Ok(HsmAesGcmDecryptContext)` - An initialized decryption context
    /// * `Err(HsmError::InvalidKey)` - If the key cannot be used for decryption
    /// * `Err(HsmError::InvalidArgument)` - If the tag was not provided
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // Check if key can decrypt
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // Tag must be provided for decryption
        if self.tag.is_none() {
            Err(HsmError::InvalidArgument)?;
        }

        Ok(HsmAesGcmDecryptContext {
            algo: self,
            key,
            buffer: Vec::with_capacity(AES_GCM_MAX_BUFFER_SIZE),
        })
    }
}

impl HsmDecryptContext for HsmAesGcmDecryptContext {
    type Algo = HsmAesGcmAlgo;

    /// Decrypts a chunk of ciphertext in the streaming operation.
    ///
    /// For AES-GCM, data is buffered until `finish` is called or the buffer
    /// reaches the maximum size. Authentication is performed during processing.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `plaintext` - Optional buffer for decrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written (may be 0 if data is buffered)
    fn update(
        &mut self,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        // Calculate how much we can buffer and how much needs to be processed
        let space_in_buffer = AES_GCM_MAX_BUFFER_SIZE.saturating_sub(self.buffer.len());
        let to_buffer = ciphertext.len().min(space_in_buffer);
        let remaining = &ciphertext[to_buffer..];

        // If buffer won't overflow and no plaintext buffer is provided, just calculate size
        if self.buffer.len() + ciphertext.len() <= AES_GCM_MAX_BUFFER_SIZE {
            // All data fits in buffer, no output yet
            if plaintext.is_none() {
                return Ok(0);
            }
            self.buffer.extend_from_slice(ciphertext);
            return Ok(0);
        }

        // Buffer will overflow, need to decrypt current buffer + overflow
        let total_to_decrypt = self.buffer.len() + to_buffer;

        // For size query
        let Some(plaintext) = plaintext else {
            // Return size of what would be decrypted
            return Ok(total_to_decrypt);
        };

        if plaintext.len() < total_to_decrypt {
            return Err(HsmError::BufferTooSmall);
        }

        // Add data to buffer
        self.buffer.extend_from_slice(&ciphertext[..to_buffer]);

        // Tag must be present (checked in decrypt_init)
        let tag = self.algo.tag.ok_or(HsmError::InvalidArgument)?;

        // Decrypt the full buffer
        let bytes_written = ddi::aes_gcm_decrypt(
            &self.key,
            self.algo.iv,
            tag,
            self.algo.aad.clone(),
            &self.buffer,
            plaintext,
        )?;

        // Clear buffer and add remaining data
        self.buffer.clear();
        self.buffer.extend_from_slice(remaining);

        Ok(bytes_written)
    }

    /// Finalizes the streaming decryption operation and produces final plaintext.
    ///
    /// Decrypts any remaining buffered data and verifies the authentication tag.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Optional buffer for final decrypted output. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written
    /// * `Err(HsmError)` - If authentication fails or decryption fails
    fn finish(
        &mut self,
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        if self.buffer.is_empty() {
            return Ok(0);
        }

        let expected_len = self.buffer.len();

        let Some(plaintext) = plaintext else {
            return Ok(expected_len);
        };

        if plaintext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        // Tag must be present
        let tag = self.algo.tag.ok_or(HsmError::InvalidArgument)?;

        let bytes_written = ddi::aes_gcm_decrypt(
            &self.key,
            self.algo.iv,
            tag,
            self.algo.aad.clone(),
            &self.buffer,
            plaintext,
        )?;

        self.buffer.clear();

        Ok(bytes_written)
    }

    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
