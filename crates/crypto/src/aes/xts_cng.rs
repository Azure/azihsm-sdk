// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows CNG (Cryptography Next Generation) implementation of AES-XTS operations.
//!
//! This module provides a Windows-specific implementation of AES-XTS (XEX-based tweaked-codebook
//! mode with ciphertext stealing) encryption and decryption using the Windows Cryptography Next
//! Generation (CNG) API. XTS mode is specifically designed for disk encryption where each sector
//! can be encrypted independently.
//!
//! # Features
//!
//! - **Native Windows integration**: Uses the platform's built-in cryptographic providers
//! - **Hardware acceleration**: Automatically leverages AES-NI and other hardware features when available
//! - **Sector-based encryption**: Each data unit (sector) is encrypted independently with a unique tweak
//! - **No authentication**: XTS provides confidentiality only, not integrity or authentication
//!
//! # Security Considerations
//!
//! - XTS requires twice the key material of other modes (e.g., AES-128-XTS uses 256 bits total)
//! - The tweak value must be unique for each data unit but can be transmitted in plaintext
//! - Input data must be a multiple of the configured data unit length
//! - XTS is designed for disk encryption, not general-purpose data encryption

use windows::Win32::Security::Cryptography::*;

use super::*;

/// Windows CNG AES-XTS encryption/decryption operation.
///
/// This structure provides a stateful interface for AES-XTS encryption and decryption
/// operations, wrapping the tweak value used for sector-based encryption.
///
/// # Thread Safety
///
/// This structure is not thread-safe as it maintains mutable state for the tweak.
/// Create separate instances for concurrent operations.
pub struct CngAesXtsAlgo {
    /// Tweak value for XTS mode.
    ///
    /// This implementation currently supports 8-byte tweaks. The tweak is stored
    /// internally as a little-endian `u64` and is incremented as data units are
    /// processed.
    tweak: u64,

    /// Data unit length (in bytes) for XTS operations.
    ///
    /// XTS operates over fixed-size data units (for example, disk sectors). Input
    /// passed to encrypt/decrypt APIs must be a multiple of this length.
    dul: usize,
}

impl CngAesXtsAlgo {
    /// AES block size in bytes (16 bytes / 128 bits)
    const BLOCK_SIZE: usize = 16;
    // Supports 8 byte tweaks only for now
    const TWEAK_SIZE: usize = 8;

    /// Creates a new AES-XTS operation with the specified tweak value and data unit length.
    ///
    /// # Arguments
    ///
    /// * `tweak` - Tweak value for XTS mode. Must be exactly 8 bytes. The tweak should be
    ///   unique for each data unit being encrypted.
    /// * `dul` - Data unit length in bytes. Must be a multiple of the AES block size (16).
    ///
    /// # Returns
    ///
    /// A new `CngAesXtsAlgo` instance configured with the specified tweak and data unit length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `tweak` is not exactly 8 bytes
    /// - `dul` is not a multiple of 16
    ///
    /// # Security
    ///
    /// The tweak must be:
    /// - Unique for each data unit (sector) being encrypted
    /// - Can be stored or transmitted in plaintext
    /// - Typically derived from the sector number or logical block address
    pub fn new(tweak: &[u8], dul: usize) -> Result<Self, CryptoError> {
        if tweak.len() != Self::TWEAK_SIZE {
            Err(CryptoError::AesXtsInvalidTweakSize)?;
        }
        let tweak_val = tweak
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| CryptoError::AesXtsInvalidTweakSize)?;
        //check if data unit length is valid
        if dul == 0 || !dul.is_multiple_of(Self::BLOCK_SIZE) {
            Err(CryptoError::AesXtsInvalidDataUnitLen)?;
        }
        Ok(CngAesXtsAlgo {
            tweak: tweak_val,
            dul,
        })
    }
    /// Returns the current tweak value.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the current 8-byte tweak value in little-endian order.
    ///
    /// # Notes
    ///
    /// The tweak value is automatically incremented once per processed data unit during
    /// encryption or decryption operations.
    pub fn tweak(&self) -> Vec<u8> {
        self.tweak.to_le_bytes().to_vec()
    }

    /// Increments the tweak value for the next data unit.
    ///
    /// Treats the tweak as a little-endian u64 integer and increments it by `inc_val`
    /// without allowing wraparound.
    fn increment_tweak(&mut self, inc_val: u64) -> Result<(), CryptoError> {
        let incremented = self
            .tweak
            .checked_add(inc_val)
            .ok_or(CryptoError::AesXtsTweakOverflow)?;

        //copy value back to tweak
        self.tweak = incremented;

        Ok(())
    }

    /// Validates that incrementing the tweak by `inc_val` will not overflow.
    /// AES XTS spec requires unique tweaks for each data unit; wraparound is not allowed.
    fn validate_tweak_increment(&self, inc_val: u64) -> Result<(), CryptoError> {
        // check if tweak + inc_val overflows u64
        let current = self.tweak;
        current
            .checked_add(inc_val)
            .ok_or(CryptoError::AesXtsTweakOverflow)?;
        Ok(())
    }

    /// Sets the data unit length property for AES-XTS mode operations.
    ///
    /// This method configures the `BCRYPT_MESSAGE_BLOCK_LENGTH` property on the
    /// XTS key handle. For AES-XTS mode, this value is used to configure the data
    /// unit length (in bytes) for the operation.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully sets the data unit length property
    /// * `Err(CryptoError)` - If setting the property fails
    ///
    /// # Errors
    ///
    /// * `AesXtsConfigError` - If the Windows CNG `BCryptSetProperty` operation fails
    ///
    /// # Notes
    ///
    /// This property must be set before performing encryption or decryption operations
    /// with the XTS key handle. The data unit length is specified in bytes and controls
    /// how the XTS mode processes data units.
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_config_dul(&self, key_handle: BCRYPT_KEY_HANDLE) -> Result<(), CryptoError> {
        // For XTS mode, we need to set the block size property
        let block_size_bytes: [u8; 4] = (self.dul as u32).to_ne_bytes();

        // SAFETY: Set the message block length property for XTS mode
        let status = unsafe {
            BCryptSetProperty(
                key_handle.into(),
                BCRYPT_MESSAGE_BLOCK_LENGTH,
                &block_size_bytes,
                0,
            )
        };

        status.ok().map_err(|_| CryptoError::AesXtsConfigError)?;
        Ok(())
    }

    /// Performs AES-XTS encryption using Windows BCrypt API.
    ///
    /// This internal method wraps the unsafe BCryptEncrypt call and handles error conversion.
    /// The input length must be an exact multiple of the configured data unit length.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Windows CNG key handle for XTS mode
    /// * `input` - Plaintext data to encrypt
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of encrypted data in bytes
    /// * `Err(CryptoError::AesXtsEncryptError)` - Encryption operation failed
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_encrypt(
        &mut self,
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut out_len = 0u32;

        //check if input is multiple of dul
        if !input.len().is_multiple_of(self.dul) {
            Err(CryptoError::AesXtsInvalidInputSize)?;
        }
        //get the flag to check if tweak increment can happen
        let is_output_valid = output.is_some();

        let units = (input.len() / self.dul) as u64;

        // avoid partial encryption if tweak increment fails
        if is_output_valid {
            self.validate_tweak_increment(units)?;
        }

        //SAFETY: Calling Bcrypt unsafe functions\
        let status = unsafe {
            BCryptEncrypt(
                key_handle,
                Some(input),
                None,                        // pbPaddingInfo must be NULL for XTS
                Some(self.tweak().as_mut()), // pbIV contains the tweak for XTS
                output,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
        };

        status.ok().map_err(|_| CryptoError::AesXtsEncryptError)?;
        //update tweak if output is some valid buf
        if is_output_valid {
            self.increment_tweak(units)?;
        }
        Ok(out_len as usize)
    }

    /// Performs AES-XTS decryption using Windows BCrypt API.
    ///
    /// This internal method wraps the unsafe BCryptDecrypt call and handles error conversion.
    /// The input length must be an exact multiple of the configured data unit length.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - Windows CNG key handle for XTS mode
    /// * `input` - Ciphertext data to decrypt
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of decrypted data in bytes
    /// * `Err(CryptoError::AesXtsDecryptError)` - Decryption operation failed
    ///
    /// # Safety
    ///
    /// Uses unsafe Windows CNG API calls but ensures proper error handling.
    #[allow(unsafe_code)]
    fn bcrypt_decrypt(
        &mut self,
        key_handle: BCRYPT_KEY_HANDLE,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        let mut out_len: u32 = 0;

        // check if input is multiple of dul
        if !input.len().is_multiple_of(self.dul) {
            Err(CryptoError::AesXtsInvalidInputSize)?;
        }
        let is_output_valid = output.is_some();
        // check if we need to increment tweak after operation
        let units = (input.len() / self.dul) as u64;

        // avoid partial encryption if tweak increment fails
        if is_output_valid {
            self.validate_tweak_increment(units)?;
        }

        // SAFETY: Calling BCrypt unsafe functions
        let status = unsafe {
            BCryptDecrypt(
                key_handle,
                Some(input),
                None,
                Some(self.tweak().as_mut()),
                output,
                &mut out_len,
                BCRYPT_FLAGS(0),
            )
        };

        status.ok().map_err(|_| CryptoError::AesXtsDecryptError)?;
        //update tweak if output was provided
        if is_output_valid {
            self.increment_tweak(units)?;
        }
        Ok(out_len as usize)
    }
}

/// Encryption operation trait implementation for AES-XTS.
///
/// This implementation enables `CngAesXtsAlgo` to be used with the generic
/// encryption operation interface.
impl EncryptOp for CngAesXtsAlgo {
    type Key = AesXtsKey;

    /// Encrypts data using AES-XTS mode.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key (32 bytes for AES-128-XTS or 64 bytes for AES-256-XTS)
    /// * `input` - Plaintext data to encrypt (must be a multiple of the configured data unit length)
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of encrypted data in bytes (same as input size)
    /// * `Err(CryptoError)` - Encryption failed
    ///
    /// # Errors
    ///
    /// * `AesXtsInvalidInputSize` - Input data length is invalid
    /// * `AesXtsEncryptError` - Windows CNG encryption operation failed
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Validate input size
        if !input.len().is_multiple_of(self.dul) {
            Err(CryptoError::AesXtsInvalidInputSize)?;
        }
        // Configure data unit length
        self.bcrypt_config_dul(key.xts_handle())?;

        // Encrypt all data, bcrypt_encrypt handles chunking internally
        self.bcrypt_encrypt(key.xts_handle(), input, output)
    }
}

/// Decryption operation trait implementation for AES-XTS.
///
/// This implementation enables `CngAesXtsAlgo` to be used with the generic
/// decryption operation interface.
impl DecryptOp for CngAesXtsAlgo {
    type Key = AesXtsKey;

    /// Decrypts data using AES-XTS mode.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key (32 bytes for AES-128-XTS or 64 bytes for AES-256-XTS)
    /// * `input` - Ciphertext data to decrypt (must be a multiple of the configured data unit length)
    /// * `output` - Optional output buffer. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Size of decrypted data in bytes (same as input size)
    /// * `Err(CryptoError)` - Decryption failed
    ///
    /// # Errors
    ///
    /// * `AesXtsInvalidInputSize` - Input data length is invalid
    /// * `AesXtsDecryptError` - Windows CNG decryption operation failed
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // check if input is multiple of dul
        if !input.len().is_multiple_of(self.dul) {
            Err(CryptoError::AesXtsInvalidInputSize)?;
        }
        // Configure data unit length
        self.bcrypt_config_dul(key.xts_handle())?;

        // Decrypt all data, bcrypt_decrypt handles chunking internally
        self.bcrypt_decrypt(key.xts_handle(), input, output)
    }
}

/// Streaming context for AES-XTS encryption operations using Windows CNG.
///
/// This structure maintains the state for a multi-step AES-XTS encryption operation.
/// It is created by `CngAesXtsAlgo::encrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `encrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to produce any remaining output
///
/// # Internal State
///
/// The context maintains:
/// - XTS algorithm instance with tweak value
/// - Windows CNG key handle
///
/// This implementation does not buffer partial data units. Each `update()` call must
/// provide input whose length is a multiple of the configured data unit length.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesXtsEncryptContext {
    algo: CngAesXtsAlgo,
    key: AesXtsKey,
}

/// Implementation of streaming encryption for AES-XTS using Windows CNG.
impl<'a> EncryptStreamingOp<'a> for CngAesXtsAlgo {
    type Key = AesXtsKey;
    type Context = CngAesXtsEncryptContext;

    /// Initializes a streaming AES-XTS encryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive encryption with intermediate buffering
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key (32 bytes for AES-128-XTS or 64 bytes for AES-256-XTS)
    ///
    /// # Returns
    ///
    /// A context implementing `EncryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data unit length configuration fails
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        // Configure CNG algo data unit len
        self.bcrypt_config_dul(key.xts_handle())?;

        //return context
        Ok(CngAesXtsEncryptContext { algo: self, key })
    }
}
/// Implementation of streaming encryption operations for the AES-XTS encrypt context.
impl<'a> EncryptOpContext<'a> for CngAesXtsEncryptContext {
    type Algo = CngAesXtsAlgo;

    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// For XTS mode, data is processed in data unit blocks (configurable size).
    /// This implementation does not buffer partial data units.
    ///
    /// # Arguments
    ///
    /// * `input` - Input data chunk to process
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`. On success, this is the same as the input size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying Windows CNG encryption operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        // process data using bcrypt_encrypt
        self.algo
            .bcrypt_encrypt(self.key.xts_handle(), input, output)
    }

    /// Finalizes the streaming operation and emits any remaining output.
    ///
    /// This implementation does not buffer data during `update()`, so `finish()`
    /// is a no-op.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(0)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - (none)
    fn finish(&mut self, _output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        // AES XTS does not buffer data in this implementation, so finish is a no-op.
        Ok(0)
    }

    /// Returns a reference to the algorithm state.
    ///
    /// This exposes the current AES-XTS configuration (including the tweak and
    /// data unit length). The tweak is updated as data units are processed.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the algorithm state.
    ///
    /// Modifying the tweak or data unit length mid-stream will affect subsequent
    /// encryption and can render the ciphertext undecryptable.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the algorithm state.
    ///
    /// This is useful if the caller needs to recover the updated tweak after a
    /// streaming operation completes.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

/// Streaming context for AES-XTS decryption operations using Windows CNG.
///
/// This structure maintains the state for a multi-step AES-XTS decryption operation.
/// It is created by `CngAesXtsAlgo::decrypt_init` and processes data incrementally
/// through `update` calls, with finalization via `finish`.
///
/// # Lifecycle
///
/// 1. Create context via `decrypt_init`
/// 2. Process data chunks with `update` (can be called multiple times)
/// 3. Finalize with `finish` to produce final output
///
/// # Internal State
///
/// The context maintains:
/// - XTS algorithm instance with tweak value
/// - Windows CNG key handle
///
/// This implementation does not buffer partial data units. Each `update()` call must
/// provide input whose length is a multiple of the configured data unit length.
///
/// # Thread Safety
///
/// This context is not thread-safe and should be used from a single thread.
pub struct CngAesXtsDecryptContext {
    algo: CngAesXtsAlgo,
    key: AesXtsKey,
}

/// Implementation of streaming decryption for AES-XTS using Windows CNG.
impl<'a> DecryptStreamingOp<'a> for CngAesXtsAlgo {
    type Key = AesXtsKey;
    type Context = CngAesXtsDecryptContext;

    /// Initializes a streaming AES-XTS decryption context.
    ///
    /// Creates a context for processing data in multiple chunks. This is useful for:
    /// - Large files that don't fit in memory
    /// - Streaming data from network or other sources
    /// - Progressive decryption with intermediate buffering
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key (32 bytes for AES-128-XTS or 64 bytes for AES-256-XTS)
    ///
    /// # Returns
    ///
    /// A context implementing `DecryptOpContext` for streaming operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The data unit length configuration fails
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        // Configure CNG algo data unit len
        self.bcrypt_config_dul(key.xts_handle())?;

        Ok(CngAesXtsDecryptContext { algo: self, key })
    }
}
/// Implementation of streaming decryption operations for the AES-XTS decrypt context.
impl<'a> DecryptOpContext<'a> for CngAesXtsDecryptContext {
    type Algo = CngAesXtsAlgo;

    /// Processes a chunk of input data.
    ///
    /// This method can be called multiple times to process data incrementally.
    /// For XTS mode, data is processed in data unit blocks (configurable size).
    /// This implementation does not buffer partial data units.
    ///
    /// # Arguments
    ///
    /// * `input` - Input ciphertext chunk to process
    /// * `output` - Optional output buffer. If `None`, returns required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer
    /// size if `output` is `None`. On success, this is the same as the input size.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The underlying Windows CNG decryption operation fails
    fn update(&mut self, input: &[u8], output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        //process data using bcrypt_decrypt
        self.algo
            .bcrypt_decrypt(self.key.xts_handle(), input, output)
    }

    /// Finalizes the streaming operation and emits any remaining output.
    ///
    /// This implementation does not buffer data during `update()`, so `finish()`
    /// is a no-op.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(0)`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - (none)
    fn finish(&mut self, _output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        // AES XTS does not buffer data in this implementation, so finish is a no-op.
        Ok(0)
    }

    /// Returns a reference to the algorithm state.
    ///
    /// This exposes the current AES-XTS configuration (including the tweak and
    /// data unit length). The tweak is updated as data units are processed.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the algorithm state.
    ///
    /// Modifying the tweak or data unit length mid-stream will affect subsequent
    /// decryption and can produce incorrect plaintext.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes the context and returns the algorithm state.
    ///
    /// This is useful if the caller needs to recover the updated tweak after a
    /// streaming operation completes.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
