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
    /// Validates and converts an IV slice to a fixed-size array.
    fn validate_iv(iv: &[u8]) -> HsmResult<[u8; GCM_IV_SIZE]> {
        iv.try_into().map_err(|_| HsmError::InvalidArgument)
    }

    /// Validates and converts a tag slice to a fixed-size array.
    fn validate_tag(tag: &[u8]) -> HsmResult<[u8; GCM_TAG_SIZE]> {
        tag.try_into().map_err(|_| HsmError::InvalidArgument)
    }

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
        let iv = Self::validate_iv(&iv)?;
        Ok(Self { iv, aad, tag: None })
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
        let iv = Self::validate_iv(&iv)?;
        let tag = Self::validate_tag(&tag)?;
        Ok(Self {
            iv,
            aad,
            tag: Some(tag),
        })
    }

    /// Returns a reference to the initialization vector.
    pub fn iv(&self) -> &[u8; GCM_IV_SIZE] {
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
            return Err(HsmError::InvalidKey);
        }

        // GCM ciphertext is same length as plaintext
        let expected_len = plaintext.len();

        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };

        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let (bytes_written, tag) =
            ddi::aes_gcm_encrypt(key, self.iv, self.aad.clone(), plaintext, ciphertext)?;

        // Store the tag from the result
        self.tag = Some(tag);

        Ok(bytes_written)
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
            return Err(HsmError::InvalidKey);
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
/// This is used for streaming operations to buffer data before sending to the device.(10MB)
const AES_GCM_MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024;

/// A context for streaming AES-GCM encryption operations.
///
/// This struct maintains the state of an ongoing AES-GCM encryption operation,
/// allowing data to be encrypted incrementally through multiple calls.
///
/// **IMPORTANT**: GCM is a message-based AEAD scheme that produces a single
/// authentication tag over the entire message. The streaming API buffers all
/// data and performs encryption only in `finish()`. This ensures correct GCM
/// semantics where one IV/AAD pair produces exactly one ciphertext+tag for the
/// complete message.
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
            return Err(HsmError::InvalidKey);
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

    /// Buffers a chunk of plaintext for encryption.
    ///
    /// **IMPORTANT**: For AES-GCM, this method only buffers data without producing
    /// any output. All encryption happens in `finish()`, which processes the entire
    /// message and produces the authentication tag. This ensures correct GCM semantics
    /// where one IV/AAD pair produces exactly one ciphertext+tag.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The plaintext data to buffer
    /// * `ciphertext` - Ignored (no output is produced until `finish()`)
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - Always returns 0 since no encryption occurs in `update()`
    ///
    /// # Errors
    ///
    /// * `Err(HsmError::InvalidArgument)` - If the total buffered data would exceed the maximum message size
    fn update(
        &mut self,
        plaintext: &[u8],
        _ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        // For size query (ciphertext is None), return 0 since GCM produces no output until finish()
        if _ciphertext.is_none() {
            return Ok(0);
        }

        // Check if adding this data would exceed the maximum message size
        if self.buffer.len().saturating_add(plaintext.len()) > AES_GCM_MAX_BUFFER_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // GCM must process the entire message at once to produce a valid tag.
        // Buffer all data; encryption happens in finish().
        self.buffer.extend_from_slice(plaintext);
        Ok(0)
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
        let expected_len = self.buffer.len();

        let Some(ciphertext) = ciphertext else {
            return Ok(expected_len);
        };

        if ciphertext.len() < expected_len {
            return Err(HsmError::BufferTooSmall);
        }

        let (bytes_written, tag) = ddi::aes_gcm_encrypt(
            &self.key,
            self.algo.iv,
            self.algo.aad.clone(),
            &self.buffer,
            ciphertext,
        )?;

        // Store the tag
        self.algo.tag = Some(tag);
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

/// A context for streaming AES-GCM decryption operations.
///
/// This struct maintains the state of an ongoing AES-GCM decryption operation,
/// allowing data to be decrypted incrementally through multiple calls.
///
/// **IMPORTANT**: GCM is a message-based AEAD scheme that verifies a single
/// authentication tag over the entire message. The streaming API buffers all
/// data and performs decryption+verification only in `finish()`. This ensures
/// correct GCM semantics where one IV/AAD/tag triple authenticates exactly one
/// complete message.
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
            return Err(HsmError::InvalidKey);
        }

        // Tag must be provided for decryption
        if self.tag.is_none() {
            return Err(HsmError::InvalidArgument);
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

    /// Buffers a chunk of ciphertext for decryption.
    ///
    /// **IMPORTANT**: For AES-GCM, this method only buffers data without producing
    /// any output. All decryption and tag verification happen in `finish()`, which
    /// processes the entire message. This ensures correct GCM semantics where one
    /// IV/AAD/tag triple authenticates exactly one complete message.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext data to buffer
    /// * `plaintext` - Ignored (no output is produced until `finish()`)
    ///
    /// # Returns
    ///
    /// * `Ok(0)` - Always returns 0 since no decryption occurs in `update()`
    ///
    /// # Errors
    ///
    /// * `Err(HsmError::InvalidArgument)` - If the total buffered data would exceed the maximum message size
    fn update(
        &mut self,
        ciphertext: &[u8],
        _plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        // For size query (plaintext is None), return 0 since GCM produces no output until finish()
        if _plaintext.is_none() {
            return Ok(0);
        }

        // Check if adding this data would exceed the maximum message size
        if self.buffer.len().saturating_add(ciphertext.len()) > AES_GCM_MAX_BUFFER_SIZE {
            return Err(HsmError::InvalidArgument);
        }

        // GCM must verify the tag over the entire message at once.
        // Buffer all data; decryption happens in finish().
        self.buffer.extend_from_slice(ciphertext);
        Ok(0)
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
