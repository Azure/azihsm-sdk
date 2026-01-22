// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES-XTS encryption and decryption operations.
//!
//! This module provides AES-XTS (XEX-based Tweaked-codebook mode with ciphertext
//! stealing) encryption and decryption for HSM AES-XTS keys.
//!
//! The implementation supports:
//! - **Single-shot** operations via [`HsmEncryptOp`] and [`HsmDecryptOp`]
//! - **Streaming** operations via [`HsmEncryptStreamingOp`] and [`HsmDecryptStreamingOp`]
//!
//! ## Data unit length (DUL)
//!
//! AES-XTS operates on *data units*. All inputs must be a multiple of the
//! configured data unit length (DUL).
//!
//! ## Stateful tweak
//!
//! The tweak is stored as internal state and is incremented by one after each
//! processed data unit.

use super::*;

/// An algorithm implementation for AES-XTS encryption and decryption.
///
/// This struct provides both single-shot and streaming AES-XTS encryption and
/// decryption operations. It implements [`HsmEncryptOp`], [`HsmDecryptOp`],
/// [`HsmEncryptStreamingOp`], and [`HsmDecryptStreamingOp`].
///
/// ## Stateful tweak
///
/// The tweak is stored internally as a `u128` (little-endian) and is advanced as
/// data units are processed.
pub struct HsmAesXtsAlgo {
    /// Current tweak value (little-endian `u128`).
    tweak: u128,

    /// Data unit length (DUL) in bytes.
    dul: usize,
}

impl HsmAesXtsAlgo {
    /// Size of the tweak in bytes.
    const TWEAK_SIZE: usize = 16;

    /// Validates the supported data unit lengths.
    ///
    /// # Arguments
    ///
    /// * `dul` - Data unit length in bytes
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if `dul` is not supported.
    fn validate_dul_size(dul: usize) -> HsmResult<()> {
        // DUL must be a positive multiple of one AES block.
        // We additionally cap DUL to keep per-unit requests bounded.
        if dul == 0 || !dul.is_multiple_of(16) || dul > 8192 {
            Err(HsmError::InvalidArgument)?;
        }
        Ok(())
    }

    /// Validates that incrementing the tweak for the given input will not overflow.
    ///
    /// # Arguments
    ///
    /// * `input` - Input buffer used to compute number of data units
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidTweak`] if incrementing would overflow.
    fn validate_tweak_increment(&self, input: &[u8]) -> HsmResult<()> {
        let blocks = input.len() / self.dul;
        // Check if tweak + inc_val overflows u64.
        let current = self.tweak;
        current
            .checked_add(blocks as u128)
            .ok_or(HsmError::InvalidTweak)?;
        Ok(())
    }

    /// Increments the internal tweak by `inc_val`.
    ///
    /// # Arguments
    ///
    /// * `inc_val` - Number of data units to advance the tweak
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidTweak`] if the increment would overflow.
    fn increment_tweak(&mut self, inc_val: usize) -> HsmResult<()> {
        self.tweak = self
            .tweak
            .checked_add(inc_val as u128)
            .ok_or(HsmError::InvalidTweak)?;
        Ok(())
    }

    /// Encrypts/decrypts data a data unit at a time.
    ///
    /// This helper enforces DUL alignment, checks output sizing, validates tweak
    /// increment safety, and advances the tweak after each processed data unit.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key to use
    /// * `input` - Input data (must be DUL-aligned)
    /// * `output` - Optional output buffer. If `None`, only calculates size.
    /// * `encrypt` - `true` to encrypt, `false` to decrypt
    ///
    /// # Returns
    ///
    /// Returns bytes written, or required size if `output` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if `input` is not DUL-aligned.
    /// Returns [`HsmError::BufferTooSmall`] if `output` is too small.
    fn crypt_data_units(
        &mut self,
        key: &HsmAesXtsKey,
        input: &[u8],
        output: Option<&mut [u8]>,
        encrypt: bool,
    ) -> HsmResult<usize> {
        // Accept only full data units
        if !input.len().is_multiple_of(self.dul) {
            Err(HsmError::InvalidArgument)?;
        }
        //return expected size if output is None
        let Some(output) = output else {
            return Ok(input.len());
        };

        // Check that the output buffer is large enough
        if output.len() < input.len() {
            Err(HsmError::BufferTooSmall)?;
        }

        //check if tweak can be incremented for the given input size
        self.validate_tweak_increment(input)?;

        let mut output_len = 0;
        let mut offset = 0;

        for unit in input.chunks(self.dul) {
            let end = offset + unit.len();
            output_len += if encrypt {
                ddi::aes_xts_encrypt(key, self.tweak, self.dul, unit, &mut output[offset..end])?
            } else {
                ddi::aes_xts_decrypt(key, self.tweak, self.dul, unit, &mut output[offset..end])?
            };
            self.increment_tweak(1)?;
            offset = end;
        }

        Ok(output_len)
    }

    /// Creates a new AES-XTS algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `tweak` - Initial tweak value (must be 16 bytes)
    /// * `dul` - Data unit length in bytes (supported: any non-zero multiple of 16 up to 8192)
    ///
    /// # Returns
    ///
    /// Returns an initialized [`HsmAesXtsAlgo`].
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if `tweak` is not 16 bytes or if `dul` is unsupported.
    pub fn new(tweak: &[u8], dul: usize) -> HsmResult<Self> {
        //validate tweak size
        if tweak.len() != Self::TWEAK_SIZE {
            Err(HsmError::InvalidArgument)?;
        }

        //convert tweak to u128 little-endian
        let tweak_val = tweak
            .try_into()
            .map(u128::from_le_bytes)
            .map_err(|_| HsmError::InvalidArgument)?;

        //validate dul size
        HsmAesXtsAlgo::validate_dul_size(dul)?;

        Ok(Self {
            tweak: tweak_val,
            dul,
        })
    }

    /// Returns the current tweak as little-endian bytes.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the 16-byte tweak.
    pub fn tweak(&self) -> Vec<u8> {
        self.tweak.to_le_bytes().to_vec()
    }
}

impl HsmEncryptOp for HsmAesXtsAlgo {
    /// The AES-XTS key type used for encryption.
    type Key = HsmAesXtsKey;

    /// The error type for encryption operations.
    type Error = HsmError;

    /// Encrypts plaintext using AES-XTS mode.
    ///
    /// The plaintext length must be a multiple of the configured data unit length (DUL).
    /// If `ciphertext` is `None`, this method returns the required output size.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key to use
    /// * `plaintext` - Plaintext data to encrypt (DUL-aligned)
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// Returns bytes written, or required size if `ciphertext` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidKey`] if the key is not permitted to encrypt.
    /// Returns [`HsmError::InvalidArgument`] if `plaintext` is not DUL-aligned.
    /// Returns [`HsmError::BufferTooSmall`] if the output buffer is too small.
    fn encrypt(
        &mut self,
        key: &Self::Key,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check that the key is suitable for encryption
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // Perform encryption
        self.crypt_data_units(key, plaintext, ciphertext, true)
    }
}

impl HsmDecryptOp for HsmAesXtsAlgo {
    /// The AES-XTS key type used for decryption.
    type Key = HsmAesXtsKey;

    /// The error type for decryption operations.
    type Error = HsmError;

    /// Decrypts ciphertext using AES-XTS mode.
    ///
    /// The ciphertext length must be a multiple of the configured data unit length (DUL).
    /// If `plaintext` is `None`, this method returns the required output size.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key to use
    /// * `ciphertext` - Ciphertext data to decrypt (DUL-aligned)
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// Returns bytes written, or required size if `plaintext` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidKey`] if the key is not permitted to decrypt.
    /// Returns [`HsmError::InvalidArgument`] if `ciphertext` is not DUL-aligned.
    /// Returns [`HsmError::BufferTooSmall`] if the output buffer is too small.
    fn decrypt(
        &mut self,
        key: &Self::Key,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, Self::Error> {
        // Check that the key is suitable for decryption
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }

        // Perform decryption
        self.crypt_data_units(key, ciphertext, plaintext, false)
    }
}

/// A context for streaming AES-XTS encryption operations.
///
/// Holds the algorithm state (including the current tweak) and the key for an
/// ongoing streaming encryption session.
pub struct HsmAesXtsEncryptContext {
    /// AES-XTS algorithm state.
    algo: HsmAesXtsAlgo,

    /// AES-XTS key used by this context.
    key: HsmAesXtsKey,
}

impl HsmEncryptStreamingOp for HsmAesXtsAlgo {
    /// The AES-XTS key type used for streaming encryption.
    type Key = HsmAesXtsKey;

    /// The error type for streaming encryption.
    type Error = HsmError;

    /// The context type for streaming encryption.
    type Context = HsmAesXtsEncryptContext;

    /// Initializes a streaming AES-XTS encryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key to use for encryption
    ///
    /// # Returns
    ///
    /// Returns an initialized [`HsmAesXtsEncryptContext`].
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidKey`] if the key is not permitted to encrypt.
    fn encrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can be used for encryption
        if !key.props().can_encrypt() {
            Err(HsmError::InvalidKey)?;
        }
        Ok(HsmAesXtsEncryptContext { algo: self, key })
    }
}

impl HsmEncryptContext for HsmAesXtsEncryptContext {
    /// The AES-XTS algorithm used by this context.
    type Algo = HsmAesXtsAlgo;

    /// Encrypts a chunk of plaintext as part of a streaming operation.
    ///
    /// This implementation requires callers to provide full data units; it does
    /// not buffer partial units.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Plaintext data (must be DUL-aligned)
    /// * `ciphertext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// Returns bytes written, or required size if `ciphertext` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if `plaintext` is not DUL-aligned.
    /// Returns [`HsmError::BufferTooSmall`] if the output buffer is too small.
    fn update(
        &mut self,
        plaintext: &[u8],
        ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        // Accept only full data units
        if !plaintext.len().is_multiple_of(self.algo.dul) {
            Err(HsmError::InvalidArgument)?;
        }

        //perform encryption
        self.algo
            .crypt_data_units(&self.key, plaintext, ciphertext, true)
    }

    /// Finalizes the streaming AES-XTS encryption operation.
    ///
    /// Since updates require full data units, there is no buffered data to flush.
    fn finish(
        &mut self,
        _ciphertext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmEncryptStreamingOp>::Error> {
        // No additional data to process in finish for AES XTS
        Ok(0)
    }

    /// Returns an immutable reference to the underlying algorithm state.
    ///
    /// This can be used to inspect algorithm parameters/state (e.g. current tweak)
    /// during a streaming operation.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm state.
    ///
    /// This is primarily used by generic helpers that need to access or mutate the
    /// algorithm while a streaming context is active.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes this context and returns the underlying algorithm.
    ///
    /// This is useful to retrieve the final algorithm state (including the current
    /// tweak) after streaming completes.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}

// Decrypt context
/// A context for streaming AES-XTS decryption operations.
///
/// Holds the algorithm state (including the current tweak) and the key for an
/// ongoing streaming decryption session.
pub struct HsmAesXtsDecryptContext {
    /// AES-XTS algorithm state.
    algo: HsmAesXtsAlgo,

    /// AES-XTS key used by this context.
    key: HsmAesXtsKey,
}

impl HsmDecryptStreamingOp for HsmAesXtsAlgo {
    /// The AES-XTS key type used for streaming decryption.
    type Key = HsmAesXtsKey;

    /// The error type for streaming decryption.
    type Error = HsmError;

    /// The context type for streaming decryption.
    type Context = HsmAesXtsDecryptContext;

    /// Initializes a streaming AES-XTS decryption operation.
    ///
    /// # Arguments
    ///
    /// * `key` - AES-XTS key to use for decryption
    ///
    /// # Returns
    ///
    /// Returns an initialized [`HsmAesXtsDecryptContext`].
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidKey`] if the key is not permitted to decrypt.
    fn decrypt_init(self, key: Self::Key) -> Result<Self::Context, Self::Error> {
        // check if key can be used for decryption
        if !key.props().can_decrypt() {
            Err(HsmError::InvalidKey)?;
        }
        Ok(HsmAesXtsDecryptContext { algo: self, key })
    }
}

impl HsmDecryptContext for HsmAesXtsDecryptContext {
    /// The AES-XTS algorithm used by this context.
    type Algo = HsmAesXtsAlgo;

    /// Decrypts a chunk of ciphertext as part of a streaming operation.
    ///
    /// This implementation requires callers to provide full data units; it does
    /// not buffer partial units.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - Ciphertext data (must be DUL-aligned)
    /// * `plaintext` - Optional output buffer. If `None`, only calculates size.
    ///
    /// # Returns
    ///
    /// Returns bytes written, or required size if `plaintext` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`HsmError::InvalidArgument`] if `ciphertext` is not DUL-aligned.
    /// Returns [`HsmError::BufferTooSmall`] if the output buffer is too small.
    fn update(
        &mut self,
        ciphertext: &[u8],
        plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        // Accept only full data units
        if !ciphertext.len().is_multiple_of(self.algo.dul) {
            Err(HsmError::InvalidArgument)?;
        }
        //perform decryption
        self.algo
            .crypt_data_units(&self.key, ciphertext, plaintext, false)
    }

    /// Finalizes the streaming AES-XTS decryption operation.
    ///
    /// Since updates require full data units, there is no buffered data to flush.
    fn finish(
        &mut self,
        _plaintext: Option<&mut [u8]>,
    ) -> Result<usize, <Self::Algo as HsmDecryptStreamingOp>::Error> {
        // No additional data to process in finish for AES XTS
        Ok(0)
    }

    /// Returns an immutable reference to the underlying algorithm state.
    ///
    /// This can be used to inspect algorithm parameters/state (e.g. current tweak)
    /// during a streaming operation.
    fn algo(&self) -> &Self::Algo {
        &self.algo
    }

    /// Returns a mutable reference to the underlying algorithm state.
    ///
    /// This is primarily used by generic helpers that need to access or mutate the
    /// algorithm while a streaming context is active.
    fn algo_mut(&mut self) -> &mut Self::Algo {
        &mut self.algo
    }

    /// Consumes this context and returns the underlying algorithm.
    ///
    /// This is useful to retrieve the final algorithm state (including the current
    /// tweak) after streaming completes.
    fn into_algo(self) -> Self::Algo {
        self.algo
    }
}
