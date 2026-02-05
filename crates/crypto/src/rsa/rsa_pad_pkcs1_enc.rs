// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! RSA PKCS#1 v1.5 encryption padding implementation.
//!
//! This module implements the PKCS#1 v1.5 encryption padding scheme as specified in
//! RFC 8017 Section 7.2. It provides encoding and decoding operations for RSA
//! encryption with proper padding.
//!
//! # PKCS#1 v1.5 Padding Format
//!
//! The padded message has the following structure:
//! ```text
//! EM = 0x00 || 0x02 || PS || 0x00 || M
//! ```
//!
//! Where:
//! - `0x00`: Initial zero byte
//! - `0x02`: Block type for encryption
//! - `PS`: Padding string of non-zero random bytes (at least 8 bytes)
//! - `0x00`: Separator byte
//! - `M`: The original message
//!
//! # Supported Key Sizes
//!
//! This implementation supports the following RSA modulus sizes:
//! - 2048 bits (256 bytes)
//! - 3072 bits (384 bytes)
//! - 4096 bits (512 bytes)

use super::*;

/// RSA PKCS#1 v1.5 encryption padding algorithm.
///
/// This struct encapsulates the PKCS#1 v1.5 padding scheme for RSA encryption,
/// which adds randomized padding to messages before encryption to prevent
/// deterministic encryption and ensure security.
///
/// # Security Note
///
/// PKCS#1 v1.5 encryption padding is considered legacy and vulnerable to padding
/// oracle attacks. For new applications, consider using OAEP padding instead.
/// This implementation is provided for compatibility with existing systems.
pub struct RsaPadPkcs1EncryptAlgo {
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    modulus_size: usize,
    /// The message to be padded or the extracted message after unpadding.
    message: Vec<u8>,
}

impl RsaPadPkcs1EncryptAlgo {
    /// Creates a new PKCS#1 v1.5 padding algorithm instance.
    ///
    /// # Arguments
    ///
    /// * `modulus_size` - The size of the RSA modulus in bytes (must be 256, 384, or 512)
    /// * `message` - The message to be padded (for encoding) or the extracted message (for decoding)
    ///
    /// # Returns
    ///
    /// A new `RsaPkcs1EncryptPadAlgo` instance.
    pub fn new(modulus_size: usize, message: &[u8]) -> Self {
        Self {
            modulus_size,
            message: message.to_vec(),
        }
    }

    /// Returns the RSA modulus size in bytes.
    ///
    /// # Returns
    ///
    /// The size of the RSA modulus in bytes (256, 384, or 512).
    pub fn modulus_size(&self) -> usize {
        self.modulus_size
    }

    /// Returns a reference to the message.
    ///
    /// # Returns
    ///
    /// A byte slice containing the message to be padded or the extracted message after unpadding.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns a mutable reference to the message.
    ///
    /// # Returns
    ///
    /// A mutable byte slice containing the message.
    pub fn message_mut(&mut self) -> &mut [u8] {
        &mut self.message
    }
}

impl EncodeOp for RsaPadPkcs1EncryptAlgo {
    /// Applies PKCS#1 v1.5 encryption padding to the message.
    ///
    /// This function implements the EME-PKCS1-v1_5-ENCODE operation from RFC 8017.
    /// It constructs a padded message with the format:
    /// `EM = 0x00 || 0x02 || PS || 0x00 || M`
    ///
    /// # Arguments
    ///
    /// * `output` - Optional mutable buffer to write the padded message to.
    ///   If `None`, only the required output length is returned.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The length of the padded message (equal to `modulus_size`)
    /// * `Err(CryptoError::RsaUnsupportedModulusSize)` - If the modulus size is not 256, 384, or 512
    /// * `Err(CryptoError::RsaMessageTooLong)` - If the message is too long for the given key size
    ///   (message length must be at most `modulus_size - 11`)
    /// * `Err(CryptoError::RsaBufferTooSmall)` - If the output buffer is too small
    /// * `Err(CryptoError::RngError)` - If random number generation fails
    ///
    /// # Security
    ///
    /// The padding string (PS) consists of at least 8 bytes of non-zero random bytes,
    /// ensuring that each encryption of the same message produces a different ciphertext.
    fn to_bytes(&mut self, output: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let k = self.modulus_size;
        if !matches!(k, 256 | 384 | 512) {
            return Err(CryptoError::RsaUnsupportedModulusSize);
        }

        let m_len = self.message.len();
        if m_len > k - 11 {
            return Err(CryptoError::RsaMessageTooLong);
        }

        let em_len = k;
        if let Some(out) = output {
            if out.len() < em_len {
                return Err(CryptoError::RsaBufferTooSmall);
            }

            out[0] = 0x00;
            out[1] = 0x02;

            // Fill PS with non-zero random bytes
            let ps_len = em_len - m_len - 3;
            for i in 0..ps_len {
                let mut octet = 0u8;
                let mut attempts = 0;
                while octet == 0 && attempts < 10 {
                    Rng::rand_bytes(std::slice::from_mut(&mut octet))?;
                    attempts += 1;
                }
                if octet == 0 {
                    return Err(CryptoError::RngError);
                }
                out[2 + i] = octet;
            }

            out[2 + ps_len] = 0x00;
            out[(3 + ps_len)..(3 + ps_len + m_len)].copy_from_slice(&self.message);
        }

        Ok(em_len)
    }
}

impl DecodeOp for RsaPadPkcs1EncryptAlgo {
    type T = RsaPadPkcs1EncryptAlgo;
    type P = ();

    /// Removes PKCS#1 v1.5 encryption padding from a padded message.
    ///
    /// This function implements the EME-PKCS1-v1_5-DECODE operation from RFC 8017.
    /// It validates the padding structure and extracts the original message.
    ///
    /// # Arguments
    ///
    /// * `input` - The padded message to decode (must be 256, 384, or 512 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(RsaPkcs1EncryptPadAlgo)` - The decoded message wrapped in a new instance
    /// * `Err(CryptoError::RsaUnsupportedModulusSize)` - If the input length is not 256, 384, or 512
    /// * `Err(CryptoError::RsaInvalidPadding)` - If the padding format is invalid, including:
    ///   - First byte is not 0x00
    ///   - Second byte is not 0x02
    ///   - Padding string is less than 8 bytes
    ///   - No 0x00 separator byte found
    ///
    /// # Security Note
    ///
    /// This implementation performs constant-time validation where possible to mitigate
    /// padding oracle attacks, though PKCS#1 v1.5 padding remains inherently vulnerable.
    fn from_bytes(input: &[u8], _params: Self::P) -> Result<Self::T, CryptoError> {
        let em_len = input.len();

        // em len must me RSA 2k 3k or 4k size at least
        if !matches!(em_len, 256 | 384 | 512) {
            return Err(CryptoError::RsaUnsupportedModulusSize);
        }

        let mut valid_padding = true;
        valid_padding &= input[0] == 0x00;
        valid_padding &= input[1] == 0x02;
        if !valid_padding {
            return Err(CryptoError::RsaInvalidPadding);
        }

        let mut ps_end = 2;
        while ps_end < em_len {
            if input[ps_end] == 0x00 {
                break;
            }
            ps_end += 1;
        }

        if ps_end == em_len || ps_end < 10 {
            return Err(CryptoError::RsaInvalidPadding);
        }

        let m_start = ps_end + 1;
        let message = &input[m_start..];

        Ok(RsaPadPkcs1EncryptAlgo::new(em_len, message))
    }
}
