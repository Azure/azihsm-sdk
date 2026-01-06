// Copyright (C) Microsoft Corporation. All rights reserved.

//! AES Key Wrap with Padding (AES-KWP) implementation.
//!
//! This module implements the AES Key Wrap with Padding algorithm as specified in
//! RFC 5649 and NIST SP 800-38F. AES-KWP extends the basic AES Key Wrap (AES-KW)
//! to support plaintext of any length by adding padding.
//!
//! # Algorithm Overview
//!
//! AES-KWP uses AES in a specific mode to provide both confidentiality and integrity for
//! wrapped keys. Unlike AES-KW, which requires input to be a multiple of 8 bytes, AES-KWP:
//! - Accepts plaintext of any length (minimum 1 byte)
//! - Automatically adds padding to reach required block alignment
//! - Uses an Alternative Initial Value (AIV) that encodes the plaintext length
//!
//! # Security Properties
//!
//! - Provides authenticated encryption for key material of any size
//! - Detects tampering or corruption of wrapped keys
//! - Suitable for wrapping keys that don't naturally align to 8-byte boundaries
//! - Length encoding in AIV provides additional integrity protection
//!
//! # Standards
//!
//! - RFC 5649: Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm
//! - NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping

use std::vec;

use super::*;

/// AES Key Wrap with Padding (AES-KWP) algorithm implementation.
///
/// Provides RFC 5649 compliant AES key wrapping with automatic padding for secure
/// encryption of cryptographic key material of any length.
///
/// # Key Wrap with Padding Process
///
/// The key wrap algorithm:
/// 1. Takes plaintext key material of any length (minimum 1 byte)
/// 2. Adds padding if necessary to reach 8-byte alignment
/// 3. Creates an Alternative Initial Value (AIV) encoding the plaintext length
/// 4. Applies AES-based wrapping using a Key Encryption Key (KEK)
/// 5. Produces ciphertext that includes integrity check via the AIV
///
/// # Alternative Initial Value (AIV)
///
/// The AIV format (8 bytes):
/// - Bytes 0-3: 0xA65959A6 (constant)
/// - Bytes 4-7: Length of plaintext in bytes (big-endian)
///
/// # Input Requirements
///
/// - Input length can be any size (minimum 1 byte, maximum limited by implementation)
/// - KEK must be a valid AES key (128, 192, or 256 bits)
/// - No manual padding required - handled automatically by the algorithm
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync`.
#[derive(Default)]
pub struct AesKeyWrapPadAlgo {}

impl AesKeyWrapPadAlgo {
    /// AIV constant prefix as specified in RFC 5649.
    ///
    /// This 4-byte constant (0xA65959A6) forms the first part of the
    /// Alternative Initial Value used in AES-KWP.
    const AIV: [u8; 4] = [0xA6, 0x59, 0x59, 0xA6];

    /// Size of the Alternative Initial Value in bytes.
    ///
    /// The AIV consists of 8 bytes: 4-byte constant prefix + 4-byte MLI.
    const AIV_SIZE: usize = 8;

    /// Verifies the Alternative Initial Value and validates padding.
    ///
    /// This method performs integrity checks on unwrapped data according to RFC 5649:
    /// 1. Verifies the AIV constant prefix matches 0xA65959A6
    /// 2. Extracts and validates the Message Length Indicator (MLI)
    /// 3. Ensures MLI is within valid range for the buffer size
    /// 4. Verifies all padding bytes are zeros
    ///
    /// # Arguments
    ///
    /// * `aiv` - The 8-byte Alternative Initial Value to verify
    /// * `buf` - The unwrapped padded plaintext buffer
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The actual plaintext length (MLI) without padding
    /// * `Err(CryptoError)` - If verification fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesAIVMismatch` - AIV constant prefix doesn't match 0xA65959A6
    /// - `CryptoError::AesInvlidMLI` - MLI is out of valid range or malformed
    /// - `CryptoError::AesInvalidPadding` - Padding bytes are not all zeros
    ///
    /// # Security
    ///
    /// This verification is critical for detecting tampering or corruption.
    /// Any failure indicates the data has been modified or the wrong key was used.
    fn verify_aiv(aiv: &[u8], buf: &[u8]) -> Result<usize, CryptoError> {
        // Step 1: Verify AIV constant prefix matches 0xA65959A6
        if aiv[0..Self::AIV.len()] != Self::AIV {
            Err(CryptoError::AesAIVMismatch)?;
        }

        // Step 2: Extract Message Length Indicator (MLI) from last 4 bytes of AIV
        // MLI is stored in big-endian format
        let mli = u32::from_be_bytes(
            aiv[Self::AIV.len()..]
                .try_into()
                .map_err(|_| CryptoError::AesInvlidMLI)?,
        ) as usize;

        // Step 3: Validate MLI is within acceptable range
        // Per RFC 5649: 8*(n-1) < MLI <= 8*n where n is number of 8-byte blocks
        let n = buf.len() / 8;
        if mli <= 8 * (n - 1) || mli > 8 * n {
            Err(CryptoError::AesInvlidMLI)?
        }

        // Step 4: Verify all padding bytes (from MLI to end of buffer) are zero
        if buf[mli..].iter().any(|&x| x != 0) {
            Err(CryptoError::AesInvalidPadding)?;
        }

        // Return actual plaintext length (without padding)
        Ok(mli)
    }
}

/// Implements key wrapping with padding (encryption) operation.
///
/// This implementation wraps (encrypts) cryptographic key material of any length
/// using the AES Key Wrap with Padding algorithm specified in RFC 5649.
impl EncryptOp for AesKeyWrapPadAlgo {
    type Key = AesKey;

    /// Wraps (encrypts) key material using AES Key Wrap with Padding.
    ///
    /// Takes plaintext key material of any length and produces wrapped (encrypted) output
    /// that includes padding and an integrity check. The output size depends on the input
    /// length and padding requirements.
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK) used to wrap the input
    /// * `input` - Plaintext key material to wrap (any length, minimum 1 byte)
    /// * `output` - Optional output buffer for wrapped key. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If wrapping fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidKeySize` - KEK size is invalid
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesEncryptError` - Wrapping operation failed
    /// - `CryptoError::AesInvalidInputSize` - Input is empty or exceeds maximum size
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Create Alternative Initial Value (AIV) for padded wrapping
        // AIV format: [0xA6, 0x59, 0x59, 0xA6, MLI (4 bytes big-endian)]
        // where MLI is the Message Length Indicator (original plaintext length)
        let mli = input.len() as u32;
        let mut aiv = [8u8; Self::AIV_SIZE];
        aiv[0..Self::AIV.len()].copy_from_slice(&Self::AIV);
        aiv[Self::AIV.len()..Self::AIV_SIZE].copy_from_slice(&mli.to_be_bytes());

        // Check if input is already a multiple of 8 bytes
        // In this case, use standard AES-KW without padding
        if input.len().is_multiple_of(8) {
            return Encrypter::encrypt(&mut AesKeyWrapAlgo::with_iv(&aiv)?, key, input, output);
        }

        // Pad plaintext to next multiple of 8 bytes
        // Padding bytes are zero-filled
        let r = input.len().next_multiple_of(8);
        let mut p = vec![0u8; r];
        p[0..input.len()].copy_from_slice(input);

        if p.len() == 8 {
            let mut buf = vec![0u8; aiv.len() + p.len()];
            // Special case: if padded plaintext is exactly 8 bytes (one semi-block)
            // Use AES ECB encryption directly instead of full key wrap algorithm
            buf[0..aiv.len()].copy_from_slice(&aiv);
            buf[aiv.len()..aiv.len() + p.len()].copy_from_slice(&p);
            Encrypter::encrypt(&mut AesEcbAlgo::default(), key, &buf, output)
        } else {
            // Standard case: use AES-KW with the constructed AIV
            Encrypter::encrypt(&mut AesKeyWrapAlgo::with_iv(&aiv)?, key, &p, output)
        }
    }
}

/// Implements key unwrapping with padding (decryption) operation.
///
/// This implementation unwraps (decrypts) cryptographic key material that was
/// wrapped using the AES Key Wrap with Padding algorithm specified in RFC 5649.
impl DecryptOp for AesKeyWrapPadAlgo {
    type Key = AesKey;

    /// Unwraps (decrypts) key material using AES Key Wrap with Padding.
    ///
    /// Takes wrapped (encrypted) key material and produces plaintext key data.
    /// Verifies the AIV integrity check and removes padding during unwrapping.
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK) used to unwrap the input
    /// * `input` - Wrapped key material to decrypt
    /// * `output` - Optional output buffer for unwrapped key. If `None`, returns required size.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - Number of bytes written to output, or required buffer size if output is `None`
    /// * `Err(CryptoError)` - If unwrapping fails
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::AesInvalidInputSize` - Input length is invalid
    /// - `CryptoError::AesInvalidKeySize` - KEK size is invalid
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesDecryptError` - Unwrapping failed (wrong key, corrupted data, or AIV verification failure)
    /// - AIV verification failure indicates tampered or corrupted wrapped key
    /// - Invalid padding indicates data corruption
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        // Validate minimum input size
        // Minimum wrapped size is 16 bytes (AIV + one semi-block)
        if input.len() < 16 {
            Err(CryptoError::AesInvalidInputSize)?;
        }

        // Special case: if input is exactly 16 bytes (AIV + one semi-block)
        // This means the original plaintext was <= 8 bytes after padding
        // Use AES ECB decryption directly instead of full key unwrap algorithm
        if input.len() == 16 {
            // Decrypt using AES ECB: result will be [AIV | padded plaintext]
            let buf = Decrypter::decrypt_vec(&mut AesEcbAlgo::default(), key, input)?;

            // Verify AIV and extract actual plaintext length (MLI)
            let len = Self::verify_aiv(&buf[0..Self::AIV_SIZE], &buf[Self::AIV_SIZE..])?;

            // Copy unpadded plaintext to output buffer if provided
            if let Some(output) = output {
                if output.len() < len {
                    Err(CryptoError::AesBufferTooSmall)?;
                }
                output[..len].copy_from_slice(&buf[Self::AIV_SIZE..Self::AIV_SIZE + len]);
            }
            Ok(len)
        } else {
            // Standard case: use AES-KW unwrap algorithm
            // Create AesKeyWrap without IV checking (we'll verify AIV separately)
            let mut kw = AesKeyWrapAlgo::with_no_iv_check();

            let len = if let Some(output) = output {
                // Decrypt and get the padded plaintext length
                let len = Decrypter::decrypt(&mut kw, key, input, Some(output))?;

                // Verify the AIV that was extracted during unwrap
                Self::verify_aiv(kw.iv(), &output[0..len])?
            } else {
                // Just return required buffer size without performing full decryption
                Decrypter::decrypt(&mut kw, key, input, None)?
            };
            Ok(len)
        }
    }
}
