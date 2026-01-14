// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based AES-XTS encryption/decryption implementation.
//!
//! This module provides AES XEX-based tweaked-codebook mode with ciphertext stealing (XTS)
//! operations using OpenSSL as the underlying cryptographic backend. XTS mode is specifically
//! designed for disk encryption where each sector can be encrypted independently.
//!
//! # XTS Mode
//!
//! XTS (XEX-based tweaked-codebook mode with ciphertext stealing) mode is designed for
//! encrypting data on block devices. It uses two keys: one for encryption and one for
//! generating the tweak. The tweak value typically represents the sector number, ensuring
//! that identical plaintext blocks at different locations produce different ciphertext.
//!
//! # Security Considerations
//!
//! - **Key Requirements**: XTS requires twice the key material of other modes
//!   (e.g., AES-128-XTS uses two 128-bit keys for a total of 256 bits)
//! - **Tweak Uniqueness**: Each data unit (typically a disk sector) must have a unique tweak value
//! - **Minimum Data Size**: Input data must be at least one block (16 bytes) in size
//! - **No Authentication**: XTS mode does not provide authentication; it only provides confidentiality
//! - **Sector-based**: Designed for disk encryption, not for general-purpose data encryption

use openssl::symm::*;

use super::*;

/// OpenSSL AES-XTS encryption/decryption operation.
///
/// This structure configures an AES-XTS operation with a tweak value. The tweak is typically
/// a sector number for disk encryption, ensuring that identical data in different sectors
/// produces different ciphertext.
///
/// # Fields
///
/// The structure maintains:
/// - Tweak value (provided as an 8-byte little-endian counter and expanded to 16 bytes for OpenSSL)
///
/// # Thread Safety
///
/// This structure can be used across multiple operations with the same tweak, but is not
/// thread-safe. For concurrent operations, create separate instances.
pub struct OsslAesXtsAlgo {
    /// Tweak value for XTS mode.
    ///
    /// The public API accepts an 8-byte tweak (little-endian) which is interpreted as a `u64`.
    /// OpenSSL expects a 16-byte tweak/IV for AES-XTS, so we expand the `u64` to 16 bytes by
    /// zero-padding the upper 8 bytes.
    tweak: u64,

    /// Data unit length (bytes) for XTS operations.
    ///
    /// Input is processed in chunks of this size. The tweak is incremented once per data unit.
    dul: usize,
}

impl OsslAesXtsAlgo {
    /// AES block size in bytes (16 bytes / 128 bits)
    const BLOCK_SIZE: usize = 16;
    const TWEAK_SIZE: usize = 8;

    /// Creates a new AES-XTS operation with the specified tweak value and data unit length.
    ///
    /// # Arguments
    ///
    /// * `tweak` - Tweak value for XTS mode. Must be exactly 8 bytes and is interpreted as a
    ///   little-endian `u64`. The tweak should be unique for each data unit being encrypted
    ///   (e.g., disk sector number).
    /// * `dul` - Data unit length in bytes. This controls how the input is split into chunks
    ///   for XTS processing. Each chunk is processed independently with an incremented tweak.
    ///   Must be a multiple of the AES block size (16 bytes).
    ///
    /// # Returns
    ///
    /// A new `OsslAesXtsAlgo` instance configured with the specified tweak.
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
        // Check if data unit length is valid.
        if dul == 0 || !dul.is_multiple_of(Self::BLOCK_SIZE) {
            Err(CryptoError::AesXtsInvalidDataUnitLen)?;
        }
        Ok(OsslAesXtsAlgo {
            tweak: tweak_val,
            dul,
        })
    }

    /// Returns the current tweak value.
    ///
    /// # Returns
    ///
    /// The 8-byte tweak value (little-endian) used for XTS operations.
    ///
    /// # Notes
    ///
    /// The tweak value is automatically incremented once per processed data unit during
    /// encryption or decryption operations.
    pub fn tweak(&self) -> Vec<u8> {
        self.tweak.to_le_bytes().to_vec()
    }

    /// Returns the appropriate OpenSSL cipher based on key size.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Total key size in bytes (32 for AES-128-XTS, 64 for AES-256-XTS)
    ///
    /// # Returns
    ///
    /// The OpenSSL cipher object for the specified key size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesXtsInvalidKeySize` if the key size is not 32 or 64 bytes.
    fn cipher(key_size: usize) -> Result<Cipher, CryptoError> {
        match key_size {
            32 => Ok(Cipher::aes_128_xts()),
            64 => Ok(Cipher::aes_256_xts()),
            _ => Err(CryptoError::AesXtsInvalidKeySize),
        }
    }

    /// Increments the tweak value for the next data unit.
    ///
    /// Treats the tweak as a little-endian `u64` counter and increments it by `inc_val`
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
        // Check if tweak + inc_val overflows u64.
        let current = self.tweak;
        current
            .checked_add(inc_val)
            .ok_or(CryptoError::AesXtsTweakOverflow)?;
        Ok(())
    }

    /// Creates and configures an OpenSSL Crypter for AES-XTS operations.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The OpenSSL cipher to use
    /// * `mode` - Encryption or decryption mode
    /// * `key_bytes` - The key material
    ///
    /// The tweak used for the operation is taken from `self.tweak` and expanded to 16 bytes.
    /// The lower 8 bytes come from the little-endian `u64`; the upper 8 bytes are zero.
    ///
    /// # Returns
    ///
    /// A configured `Crypter` with padding disabled (required for XTS mode).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesXtsEncryptError` or `CryptoError::AesXtsDecryptError`
    /// depending on the mode if crypter creation fails.
    fn init_crypter(
        &self,
        cipher: Cipher,
        mode: Mode,
        key_bytes: &[u8],
    ) -> Result<Crypter, CryptoError> {
        // get tweak expanded to block size
        let full_tweak = (self.tweak as u128).to_le_bytes();

        // Initialize and configure OpenSSL Crypter for AES-XTS
        let mut crypter =
            Crypter::new(cipher, mode, key_bytes, Some(&full_tweak)).map_err(|_| match mode {
                Mode::Encrypt => CryptoError::AesXtsEncryptError,
                Mode::Decrypt => CryptoError::AesXtsDecryptError,
            })?;
        // Disable padding for XTS mode
        crypter.pad(false);

        Ok(crypter)
    }

    /// Encrypts or decrypts one data block (chunk) using AES-XTS.
    ///
    /// This helper exists to share the common OpenSSL `Crypter` setup and
    /// `update`/`finalize` flow between encrypt and decrypt.
    ///
    /// # Arguments
    ///
    /// * `cipher` - The OpenSSL cipher to use
    /// * `mode` - Encryption or decryption mode
    /// * `key_bytes` - The AES-XTS key material
    /// * `input` - The input chunk to process
    /// * `output` - Output buffer for the processed chunk (must be at least `input.len()`)
    ///
    /// # Returns
    ///
    /// The number of bytes written (always equals `input.len()` for XTS with padding disabled).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesXtsEncryptError` or `CryptoError::AesXtsDecryptError`
    /// depending on the mode if the OpenSSL operation fails.
    fn crypt_chunk(
        &self,
        cipher: Cipher,
        mode: Mode,
        key_bytes: &[u8],
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let mut crypter = self.init_crypter(cipher, mode, key_bytes)?;

        let mut count = crypter.update(input, output).map_err(|_| match mode {
            Mode::Encrypt => CryptoError::AesXtsEncryptError,
            Mode::Decrypt => CryptoError::AesXtsDecryptError,
        })?;
        count += crypter
            .finalize(&mut output[count..])
            .map_err(|_| match mode {
                Mode::Encrypt => CryptoError::AesXtsEncryptError,
                Mode::Decrypt => CryptoError::AesXtsDecryptError,
            })?;

        // With XTS + padding disabled, output should match the input length.
        if count != input.len() {
            Err(match mode {
                Mode::Encrypt => CryptoError::AesXtsEncryptError,
                Mode::Decrypt => CryptoError::AesXtsDecryptError,
            })?;
        }

        Ok(count)
    }

    /// Encrypts or decrypts a contiguous sequence of whole data units.
    ///
    /// This helper splits `input` into `self.dul` chunks, processes each chunk with the
    /// current tweak, and increments the tweak once per data unit.
    ///
    /// # Arguments
    ///
    /// * `mode` - Encryption or decryption mode
    /// * `key` - The AES-XTS key
    /// * `input` - Input bytes to process (must be a multiple of `self.dul`)
    /// * `output` - Optional output buffer. If `None`, returns the required output size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `output` (always equals `input.len()` on success).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input size is not a multiple of the data unit length
    /// - The output buffer is too small
    /// - The tweak would overflow while processing the data units
    /// - The key size is invalid
    /// - The underlying OpenSSL operation fails
    fn crypt_data_units(
        &mut self,
        mode: Mode,
        key: &AesXtsKey,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        //check if input size is multiple of data unit length
        if !input.len().is_multiple_of(self.dul) {
            Err(CryptoError::AesXtsInvalidInputSize)?;
        }

        //process data units if output buffer is provided
        if let Some(output) = output {
            //check if output buffer is large enough
            if output.len() < input.len() {
                Err(CryptoError::AesXtsBufferTooSmall)?;
            }

            // Avoid partially writing output and then failing mid-loop.
            // One tweak increment is performed per data unit.
            let data_units = input.len() / self.dul;

            // Validate that incrementing the tweak by the number of data units will not overflow.
            self.validate_tweak_increment(data_units as u64)?;

            let mut offset = 0usize;

            // Extract key bytes.
            let key_bytes = key.bytes();

            //get cipher based on key size
            let cipher = Self::cipher(key.size())?;

            for unit in input.chunks(self.dul) {
                let out_end = offset + unit.len();

                // OpenSSL does not expose the evolving tweak, so we create a new Crypter
                // per data unit with the current tweak.
                self.crypt_chunk(cipher, mode, key_bytes, unit, &mut output[offset..out_end])?;

                offset = out_end;
                self.increment_tweak(1)?;
            }

            Ok(offset)
        } else {
            // If output is None, just return the input length as the required output size.
            Ok(input.len())
        }
    }
}

/// Encryption operation implementation for AES-XTS using OpenSSL.
impl EncryptOp for OsslAesXtsAlgo {
    type Key = AesXtsKey;

    /// Encrypts data using AES-XTS mode.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key (32 bytes for AES-128-XTS, 64 bytes for AES-256-XTS)
    /// * `input` - Plaintext data to encrypt (must be a multiple of the data unit length)
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size if
    /// `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input size is not a multiple of the data unit length
    /// - The tweak size is invalid
    /// - The key size is invalid
    /// - The output buffer is too small
    /// - The underlying OpenSSL operation fails
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        //call crypt data units with encrypt mode
        self.crypt_data_units(Mode::Encrypt, key, input, output)
    }
}

/// Decryption operation implementation for AES-XTS using OpenSSL.
impl DecryptOp for OsslAesXtsAlgo {
    type Key = AesXtsKey;

    /// Decrypts data using AES-XTS mode.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key (32 bytes for AES-128-XTS, 64 bytes for AES-256-XTS)
    /// * `input` - Ciphertext data to decrypt (must be a multiple of the data unit length)
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer, or the required buffer size if
    /// `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input size is not a multiple of the data unit length
    /// - The tweak size is invalid
    /// - The key size is invalid
    /// - The output buffer is too small
    /// - The underlying OpenSSL operation fails
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        self.crypt_data_units(Mode::Decrypt, key, input, output)
    }
}

/// AES-XTS streaming encryption context (OpenSSL backend).
///
/// This context does not buffer data. Each `update()` call must provide input whose
/// length is a multiple of the configured data unit length (`dul`). The tweak is
/// incremented once per processed data unit.
pub struct OsslAesXtsEncryptContext {
    algo: OsslAesXtsAlgo,
    key: AesXtsKey,
}

impl<'a> EncryptStreamingOp<'a> for OsslAesXtsAlgo {
    type Key = AesXtsKey;
    type Context = OsslAesXtsEncryptContext;

    /// Initializes a streaming AES-XTS encryption context.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key
    ///
    /// # Returns
    ///
    /// A streaming context that can be used with `update()`/`finish()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tweak size or key size is invalid.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(OsslAesXtsEncryptContext { algo: self, key })
    }
}

/// Streaming encryption operation implementation for OpenSSL AES-XTS.
///
/// `update()` processes whole data units.
/// `finish()` is a no-op for this backend.
impl<'a> EncryptOpContext<'a> for OsslAesXtsEncryptContext {
    type Algo = OsslAesXtsAlgo;

    /// Encrypts input data in a streaming fashion.
    ///
    /// The input length must be a multiple of the configured data unit length (`dul`).
    ///
    /// # Arguments
    ///
    /// * `input` - Plaintext bytes to add to the stream
    /// * `output` - Optional output buffer. If `None`, returns the number of bytes that would be written.
    ///
    /// # Returns
    ///
    /// Number of bytes written (or that would be written) for complete data units.
    ///
    /// # Errors
    ///
    /// Returns an error if the output buffer is too small or the OpenSSL operation fails.
    fn update(
        &mut self,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        self.algo
            .crypt_data_units(Mode::Encrypt, &self.key, input, output)
    }

    /// Finalizes streaming encryption.
    ///
    /// This backend does not buffer, so `finish()` is a no-op.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required).
    ///
    /// # Errors
    ///
    /// Returns an error if the final buffered length is not a multiple of the data unit length,
    /// the output buffer is too small, or the OpenSSL operation fails.
    fn finish(&mut self, _output: Option<&mut [u8]>) -> Result<usize, super::CryptoError> {
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

/// AES-XTS streaming decryption context (OpenSSL backend).
///
/// This context does not buffer data. Each `update()` call must provide input whose
/// length is a multiple of the configured data unit length (`dul`). The tweak is
/// incremented once per processed data unit.
pub struct OsslAesXtsDecryptContext {
    algo: OsslAesXtsAlgo,
    key: AesXtsKey,
}

impl<'a> DecryptStreamingOp<'a> for OsslAesXtsAlgo {
    type Key = AesXtsKey;
    type Context = OsslAesXtsDecryptContext;

    /// Initializes a streaming AES-XTS decryption context.
    ///
    /// # Arguments
    ///
    /// * `key` - The AES-XTS key
    ///
    /// # Returns
    ///
    /// A streaming context that can be used with `update()`/`finish()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the tweak size or key size is invalid.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, CryptoError> {
        Ok(OsslAesXtsDecryptContext { algo: self, key })
    }
}

/// Streaming decryption operation implementation for OpenSSL AES-XTS.
///
/// `update()` processes whole data units.
/// `finish()` is a no-op for this backend.
impl<'a> DecryptOpContext<'a> for OsslAesXtsDecryptContext {
    type Algo = OsslAesXtsAlgo;

    /// Decrypts input data in a streaming fashion.
    ///
    /// The input length must be a multiple of the configured data unit length (`dul`).
    ///
    /// # Arguments
    ///
    /// * `input` - Ciphertext bytes to add to the stream
    /// * `output` - Optional output buffer. If `None`, returns the number of bytes that would be written.
    ///
    /// # Returns
    ///
    /// Number of bytes written (or that would be written) for complete data units.
    ///
    /// # Errors
    ///
    /// Returns an error if the output buffer is too small or the OpenSSL operation fails.
    fn update(
        &mut self,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, super::CryptoError> {
        //call crypt data units with decrypt mode
        self.algo
            .crypt_data_units(Mode::Decrypt, &self.key, input, output)
    }

    /// Finalizes streaming decryption.
    ///
    /// This backend does not buffer, so `finish()` is a no-op.
    ///
    /// # Arguments
    ///
    /// * `output` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Number of bytes written (or required).
    ///
    /// # Errors
    ///
    /// Returns an error if the final buffered length is not a multiple of the data unit length,
    /// the output buffer is too small, or the OpenSSL operation fails.
    fn finish(&mut self, _output: Option<&mut [u8]>) -> Result<usize, super::CryptoError> {
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
    /// decryption and can cause authentication/validation failures at higher
    /// layers (or produce incorrect plaintext).
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
