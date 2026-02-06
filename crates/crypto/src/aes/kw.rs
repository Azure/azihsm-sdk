// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AES Key Wrap (AES-KW) implementation.
//!
//! This module implements the AES Key Wrap algorithm as specified in RFC 3394 and NIST SP 800-38F.
//! AES Key Wrap is used to encrypt (wrap) cryptographic key material for secure storage or
//! transmission.
//!
//! # Algorithm Overview
//!
//! AES-KW uses AES in a specific mode to provide both confidentiality and integrity for
//! wrapped keys. The algorithm uses:
//! - A Key Encryption Key (KEK) to wrap the target key
//! - An 8-byte Initialization Vector (IV), default is 0xA6A6A6A6A6A6A6A6
//! - Input must be a multiple of 8 bytes (64 bits)
//!
//! # Security Properties
//!
//! - Provides authenticated encryption for key material
//! - Detects tampering or corruption of wrapped keys
//! - Suitable for wrapping symmetric and asymmetric key material
//!
//! # Standards
//!
//! - RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
//! - NIST SP 800-38F: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping

use super::*;

/// AES Key Wrap (AES-KW) algorithm implementation.
///
/// Provides RFC 3394 compliant AES key wrapping for secure encryption of cryptographic
/// key material. The implementation supports both default and custom initialization vectors.
///
/// # Key Wrap Process
///
/// The key wrap algorithm:
/// 1. Takes plaintext key material (must be multiple of 8 bytes)
/// 2. Applies AES-based wrapping using a Key Encryption Key (KEK)
/// 3. Produces ciphertext that is 8 bytes longer than input
/// 4. Includes integrity check via the IV
///
/// # Initialization Vector
///
/// - Default IV: 0xA6A6A6A6A6A6A6A6 (as specified in RFC 3394)
/// - Custom IV: Can be set via `with_iv()` for alternative integrity check values
///
/// # Input Requirements
///
/// - Input length must be a multiple of 8 bytes
/// - Minimum input size is typically 16 bytes (128 bits)
/// - KEK must be a valid AES key (128, 192, or 256 bits)
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync`.
pub struct AesKeyWrapAlgo {
    /// Initialization vector for key wrapping.
    ///
    /// Default value is 0xA6A6A6A6A6A6A6A6 as specified in RFC 3394.
    /// Custom values can be used for alternative integrity check values (AIV).
    iv: [u8; Self::IV_SIZE],

    /// Flag to skip IV integrity check during unwrapping.
    skip_iv_check: bool,
}

impl AesKeyWrapAlgo {
    /// Size of the initialization vector in bytes (64 bits).
    const IV_SIZE: usize = 8;

    /// Default initialization vector as specified in RFC 3394.
    ///
    /// This value (0xA6A6A6A6A6A6A6A6) provides the standard integrity check.
    const DEFAULT_IV: [u8; 8] = [0xA6; Self::IV_SIZE];

    /// AES block size in bytes (128 bits).
    ///
    /// Input data must be a multiple of this block size.
    const BLOCK_SIZE: usize = 16;

    /// Creates a new AES Key Wrap instance with the default RFC 3394 IV.
    ///
    /// The default IV (0xA6A6A6A6A6A6A6A6) provides the standard integrity check
    /// value for key wrapping operations.
    ///
    /// # Returns
    ///
    /// A new `AesKeyWrap` instance ready for wrapping/unwrapping operations.
    pub fn with_default_iv() -> Self {
        Self {
            iv: Self::DEFAULT_IV,
            skip_iv_check: false,
        }
    }

    /// Creates a new AES Key Wrap instance with a custom IV.
    ///
    /// Custom IVs can be used for Alternative Integrity Check Values (AIV) as
    /// described in NIST SP 800-38F. This allows for application-specific
    /// integrity verification.
    ///
    /// # Arguments
    ///
    /// * `iv` - Custom initialization vector (must be exactly 8 bytes)
    ///
    /// # Returns
    ///
    /// * `Ok(AesKeyWrap)` - New instance with custom IV
    /// * `Err(CryptoError::AesInvalidIVSize)` - If IV is not 8 bytes
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidIVSize` if the provided IV length is not 8 bytes.
    pub fn with_iv(iv: &[u8]) -> Result<Self, CryptoError> {
        if iv.len() != Self::IV_SIZE {
            return Err(CryptoError::AesInvalidIVSize);
        }

        let mut iv_array = [0u8; Self::IV_SIZE];
        iv_array.copy_from_slice(iv);
        Ok(Self {
            iv: iv_array,
            skip_iv_check: false,
        })
    }

    /// Creates a new AES Key Wrap instance that skips IV integrity checking during unwrap.
    ///
    /// This is an internal method used when the IV needs to be extracted and verified
    /// separately, such as in AES-KWP where the IV contains the Alternative Initial Value.
    ///
    /// # Returns
    ///
    /// A new `AesKeyWrap` instance with IV checking disabled.
    ///
    /// # Security Warning
    ///
    /// Disabling IV checks bypasses the integrity verification. The caller is responsible
    /// for validating the IV separately to ensure data integrity.
    pub(crate) fn with_no_iv_check() -> Self {
        Self {
            iv: [0u8; Self::IV_SIZE],
            skip_iv_check: true,
        }
    }

    /// Returns a reference to the initialization vector.
    ///
    /// After unwrapping, this contains the IV that was extracted from the wrapped data.
    /// This can be used to verify alternative integrity check values or extract
    /// application-specific data encoded in the IV.
    ///
    /// # Returns
    ///
    /// A byte slice containing the 8-byte IV.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Internal implementation of AES Key Wrap encryption algorithm.
    ///
    /// Implements the key wrap algorithm as specified in RFC 3394 Section 2.2.1.
    /// The algorithm performs 6 * n rounds where n is the number of 64-bit blocks
    /// in the input.
    ///
    /// # Algorithm Steps
    ///
    /// 1. Initialize A with the IV
    /// 2. Copy input plaintext to R[1]..R[n]
    /// 3. For j = 0 to 5:
    ///    - For i = 1 to n:
    ///      - B = AES(KEK, A | R[i])
    ///      - A = MSB(64, B) XOR t where t = (n*j)+i
    ///      - R[i] = LSB(64, B)
    /// 4. Output C[0] = A, C[1]..C[n] = R[1]..R[n]
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK)
    /// * `input` - Plaintext key material to wrap
    /// * `output` - Output buffer for wrapped key (must be input.len() + 8 bytes)
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError` if AES encryption operations fail.
    fn encrypt_kw(
        &mut self,
        key: &AesKey,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = (input.len() / Self::IV_SIZE) as u64;

        // Set A = IV, an initial value
        // R[1]..R[n] = P[1]..P[n]
        output[..Self::IV_SIZE].copy_from_slice(&self.iv);
        output[Self::IV_SIZE..].copy_from_slice(input);

        let mut ecb = AesEcbAlgo::default();

        let mut pt = [0u8; Self::BLOCK_SIZE];
        // OpenSSL Requires output buffer to be a block size larger than input buffer
        let mut ct = [0u8; Self::BLOCK_SIZE * 2];

        for j in 0..6u64 {
            for i in 1..n + 1 {
                let idx = i as usize * Self::IV_SIZE;

                // B = AES(K, A | R[i])
                pt[..Self::IV_SIZE].copy_from_slice(&output[..Self::IV_SIZE]);
                pt[Self::IV_SIZE..].copy_from_slice(&output[idx..idx + Self::IV_SIZE]);
                Encrypter::encrypt(&mut ecb, key, &pt, Some(&mut ct))?;

                // A = MSB(64, B) ^ t where t = (n*j)+i
                let t = n * j + i;
                let t_bytes = t.to_be_bytes();
                output[..Self::IV_SIZE].copy_from_slice(&ct[..Self::IV_SIZE]);
                for (x, y) in output[..Self::IV_SIZE].iter_mut().zip(&t_bytes) {
                    *x ^= *y;
                }

                // R[i] = LSB(64, B)
                output[idx..idx + Self::IV_SIZE]
                    .copy_from_slice(&ct[Self::IV_SIZE..2 * Self::IV_SIZE]);
            }
        }

        Ok(output.len())
    }

    /// Internal implementation of AES Key Wrap decryption algorithm.
    ///
    /// Implements the key unwrap algorithm as specified in RFC 3394 Section 2.2.2.
    /// The algorithm performs 6 * n rounds where n is the number of 64-bit blocks
    /// in the wrapped key (excluding the IV).
    ///
    /// # Algorithm Steps
    ///
    /// 1. Initialize A = C[0], R[1]..R[n] = C[1]..C[n]
    /// 2. For j = 5 to 0 (reversed):
    ///    - For i = n to 1 (reversed):
    ///      - B = AES-1(KEK, (A XOR t) | R[i]) where t = n*j+i
    ///      - A = MSB(64, B)
    ///      - R[i] = LSB(64, B)
    /// 3. Verify A == IV (integrity check)
    /// 4. Output P[1]..P[n] = R[1]..R[n]
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK)
    /// * `input` - Wrapped key material to decrypt
    /// * `output` - Output buffer for unwrapped key (must be input.len() - 8 bytes)
    ///
    /// # Returns
    ///
    /// The number of bytes written to the output buffer.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesDecryptError` if:
    /// - AES decryption operations fail
    /// - IV verification fails (indicates wrong key or tampered data)
    fn decrypt_kw(
        &mut self,
        key: &AesKey,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, CryptoError> {
        let n = (input.len() / Self::IV_SIZE) as u64 - 1;
        let mut ecb = AesEcbAlgo::default();
        let mut ct = [0u8; Self::BLOCK_SIZE];
        // OpenSSL Requires output buffer to be a block size larger than input buffer
        let mut pt = [0u8; Self::BLOCK_SIZE * 2];
        let mut a = [0u8; Self::IV_SIZE];

        a.copy_from_slice(&input[..Self::IV_SIZE]);
        output.copy_from_slice(&input[Self::IV_SIZE..]);

        for j in (0..6u64).rev() {
            for i in (1..n + 1).rev() {
                let idx = i as usize * Self::IV_SIZE;
                let output = &mut output[idx - Self::IV_SIZE..idx];

                // t = (n*j)+i
                let t = n * j + i;
                let t_bytes = t.to_be_bytes();

                // A = A ^ t
                for (x, y) in a.iter_mut().zip(&t_bytes) {
                    *x ^= *y;
                }

                // B = AES-1(K, A | R[i])
                ct[..Self::IV_SIZE].copy_from_slice(&a);
                ct[Self::IV_SIZE..].copy_from_slice(output);
                Decrypter::decrypt(&mut ecb, key, &ct, Some(&mut pt))?;

                // A = MSB(64, B)
                a.copy_from_slice(&pt[..Self::IV_SIZE]);

                // R[i] = LSB(64, B)
                output.copy_from_slice(&pt[Self::IV_SIZE..2 * Self::IV_SIZE]);
            }
        }

        if !self.skip_iv_check && a != self.iv {
            return Err(CryptoError::AesDecryptError);
        } else {
            self.iv.copy_from_slice(&a);
        }

        Ok(output.len())
    }
}

/// Implements key wrapping (encryption) operation.
///
/// This implementation wraps (encrypts) cryptographic key material using the
/// AES Key Wrap algorithm specified in RFC 3394.
impl EncryptOp for AesKeyWrapAlgo {
    type Key = AesKey;

    /// Wraps (encrypts) key material using AES Key Wrap.
    ///
    /// Takes plaintext key material and produces wrapped (encrypted) output that
    /// includes an integrity check. The output will be 8 bytes longer than the input.
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK) used to wrap the input
    /// * `input` - Plaintext key material to wrap (must be multiple of 8 bytes)
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
    /// - `CryptoError::AesInvalidInputSize` - Input length is not a multiple of 8 bytes
    /// - `CryptoError::AesInvalidKeySize` - KEK size is invalid
    /// - `CryptoError::AesBufferTooSmall` - Output buffer is too small
    /// - `CryptoError::AesEncryptError` - Wrapping operation failed
    fn encrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        if !input.len().is_multiple_of(Self::IV_SIZE) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let expected_len = input.len() + Self::IV_SIZE;

        let len = if let Some(output) = output {
            if output.len() < expected_len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            let actual_len = self.encrypt_kw(key, input, &mut output[..expected_len])?;
            debug_assert!(actual_len == expected_len);
            actual_len
        } else {
            expected_len
        };

        Ok(len)
    }
}

/// Implements key unwrapping (decryption) operation.
///
/// This implementation unwraps (decrypts) cryptographic key material using the
/// AES Key Wrap algorithm specified in RFC 3394.
impl DecryptOp for AesKeyWrapAlgo {
    type Key = AesKey;

    /// Unwraps (decrypts) key material using AES Key Wrap.
    ///
    /// Takes wrapped (encrypted) key material and produces plaintext key data.
    /// Verifies the integrity check value during unwrapping. The output will be
    /// 8 bytes shorter than the input.
    ///
    /// # Arguments
    ///
    /// * `key` - The Key Encryption Key (KEK) used to unwrap the input
    /// * `input` - Wrapped key material to decrypt (must be multiple of 8 bytes)
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
    /// - `CryptoError::AesDecryptError` - Unwrapping failed (wrong key or corrupted data)
    /// - Integrity check failure indicates tampered or corrupted wrapped key
    fn decrypt(
        &mut self,
        key: &Self::Key,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError> {
        if !input.len().is_multiple_of(Self::IV_SIZE) {
            return Err(CryptoError::AesInvalidInputSize);
        }

        let expected_len = input.len() - Self::IV_SIZE;

        let len = if let Some(output) = output {
            if output.len() < expected_len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            let actual_len = self.decrypt_kw(key, input, &mut output[..expected_len])?;
            debug_assert!(actual_len == input.len() - Self::IV_SIZE);
            actual_len
        } else {
            expected_len
        };

        Ok(len)
    }
}
