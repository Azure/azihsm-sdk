// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! AES CBC Library support

#[cfg(target_os = "linux")]
mod aes_ossl;

#[cfg(target_os = "windows")]
mod aes_cng;

pub(crate) use crate::CryptoError;

/// Supported AES Key size.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum AesKeySize {
    /// 128-bit key.
    Aes128,

    /// 192-bit key.
    Aes192,

    /// 256-bit key.
    Aes256,
}

impl AesKeySize {
    /// Returns the key size in bytes.
    ///
    /// # Returns
    /// * `16` for AES-128
    /// * `24` for AES-192
    /// * `32` for AES-256
    pub fn key_len(self) -> usize {
        match self {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes192 => 24,
            AesKeySize::Aes256 => 32,
        }
    }

    /// Returns the key size in bits.
    pub fn key_bits(self) -> usize {
        match self {
            AesKeySize::Aes128 => 128,
            AesKeySize::Aes192 => 192,
            AesKeySize::Aes256 => 256,
        }
    }
}

/// Padding enable/disable option for AES CBC operations.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AesCbcPadding {
    /// Use PKCS#7 padding (adds padding bytes to align data to the AES block size).
    Pkcs7,
}

/// AES Key. Encrypt and decrypt operations are based on AesKey only
#[derive(Debug, Clone)]
pub struct AesKey {
    key: Vec<u8>,
}

/// Result of the `encrypt`.
/// The result of an AES-CBC encryption operation.
///
/// Contains the encrypted ciphertext and, if applicable, the output
/// initialization vector (IV) used for CBC mode.
///
/// # Fields
/// - `cipher_text`: The resulting encrypted data as a vector of bytes.
/// - `iv`: The output initialization vector used for encryption in CBC mode.
///   This is `Some(Vec<u8>)` if an IV was generated or used, otherwise `None`.
pub struct AesCbcEncryptResult {
    /// The encrypted ciphertext produced by the AES-CBC encryption operation.
    pub cipher_text: Vec<u8>,
    /// Output IV
    pub iv: Vec<u8>,
}

/// Result of the `decrypt`.
pub struct AesCbcDecryptResult {
    /// The decrypted plaintext produced by the AES-CBC decryption operation.
    pub plain_text: Vec<u8>,
    /// Output IV
    pub iv: Vec<u8>,
}

/// Trait for AES-CBC key operations, including key generation and key construction from raw bytes.
pub trait AesCbcKeyOp {
    /// Generates a random AES key of the specified size.
    ///
    /// # Arguments
    ///
    /// * `key_size` - The desired AES key size.
    ///
    /// # Returns
    ///
    /// * `Result<AesKey, CryptoError>` - Returns `Ok` with the generated `AesKey` on success,
    ///   or `Err(CryptoError)` if random key generation fails.
    fn aes_cbc_generate_key(&self, key_size: AesKeySize) -> Result<AesKey, CryptoError>;

    /// Constructs an AES key from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `key` - A slice of bytes representing the AES key material.
    ///
    /// # Returns
    ///
    /// * `Result<AesKey, CryptoError>` - Returns `Ok` with the constructed `AesKey` on success,
    ///   or `Err(CryptoError)` if the key is invalid.
    fn from_slice(key: &[u8]) -> Result<AesKey, CryptoError>;
}

/// Trait for AES-CBC encryption operations, including single-shot and context-based encryption.
pub trait AesCbcOp {
    /// Encrypts data in a single shot using AES CBC mode.
    ///
    /// # Arguments
    /// * `data` - The plaintext data to encrypt.
    /// * `iv` - Optional initialization vector. If None, a random IV is generated.
    ///
    /// # Returns
    /// * `Result<AesCbcEncryptResult, CryptoError>` - Ok with ciphertext and IV, or an error if encryption fails.
    fn aes_cbc_encrypt(
        &self,
        data: &[u8],
        iv: Option<&[u8]>,
        padding: Option<AesCbcPadding>,
    ) -> Result<AesCbcEncryptResult, CryptoError>;

    /// Decrypts data in a single shot using AES CBC mode.
    ///
    /// # Arguments
    /// * `cipher_text` - The ciphertext data to decrypt.
    /// * `iv` - Optional initialization vector. If None, an all-zero IV is used.
    ///
    /// # Returns
    /// * `Result<AesCbcDecryptResult, CryptoError>` - Ok with plaintext and IV, or an error if decryption fails.
    fn aes_cbc_decrypt(
        &self,
        cipher_text: &[u8],
        iv: &[u8],
        padding: Option<AesCbcPadding>,
    ) -> Result<AesCbcDecryptResult, CryptoError>;

    /// Initializes an AES CBC encryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Initialization vector as a byte vector.
    ///
    /// # Returns
    /// * `Result<impl AesCbcEncryptContextOp, CryptoError>` - Ok with the encryption context, or an error if initialization fails.
    fn aes_cbc_encrypt_init(
        &self,
        iv: Option<&[u8]>,
        padding: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcEncryptContextOp, CryptoError>;

    /// Initializes an AES CBC decryption context with the given IV.
    ///
    /// # Arguments
    /// * `iv` - Optional initialization vector as a byte slice. If None or empty, returns an error.
    ///
    /// # Returns
    /// * `Result<impl AesCbcDecryptContextOp, CryptoError>` - Ok with the decryption context, or an error if initialization fails.
    fn aes_cbc_decrypt_init(
        &self,
        iv: &[u8],
        padding: Option<AesCbcPadding>,
    ) -> Result<impl AesCbcDecryptContextOp, CryptoError>;
}

/// Trait for AES-CBC encryption context operations, supporting chunked encryption and finalization.
///
/// This trait allows encrypting data in multiple chunks using the CBC mode and finalizing the encryption
/// to produce the complete ciphertext.
pub trait AesCbcEncryptContextOp {
    /// Encrypts a chunk of plaintext in CBC mode and accumulates the ciphertext.
    ///
    /// # Arguments
    /// * `data` - The plaintext chunk to encrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if encryption fails.
    fn aes_cbc_encrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalizes the CBC encryption context, processes any remaining data, and writes the full ciphertext to the output buffer.
    ///
    /// # Arguments
    /// * `cipher_text` - Output buffer to receive the full encrypted ciphertext. Must be large enough to hold the result.
    ///
    /// # Returns
    /// * `Result<usize, CryptoError>` - Ok with the number of bytes written, or an error if encryption fails or the buffer is too small.
    fn aes_cbc_encrypt_final(self) -> Result<AesCbcEncryptResult, CryptoError>;
}

/// Trait for AES-CBC decryption context operations, supporting chunked decryption and finalization.
///
/// This trait allows decrypting data in multiple chunks using the CBC mode and finalizing the decryption
/// to produce the complete plaintext.
pub trait AesCbcDecryptContextOp {
    /// Decrypts a chunk of ciphertext in CBC mode and accumulates the plaintext.
    ///
    /// # Arguments
    /// * `data` - The ciphertext chunk to decrypt.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if decryption fails.
    fn aes_cbc_decrypt_update(&mut self, data: &[u8]) -> Result<(), CryptoError>;

    /// Finalizes the CBC decryption context, processes any remaining data, and writes the full plaintext to the output buffer.
    ///
    /// # Arguments
    /// * `plain_text` - Output buffer to receive the full decrypted plaintext. Must be large enough to hold the result.
    ///
    /// # Returns
    /// * `Result<(), CryptoError>` - Ok if successful, or an error if decryption fails or the buffer is too small.
    fn aes_cbc_decrypt_final(self) -> Result<AesCbcDecryptResult, CryptoError>;
}

/// AES-CBC encryption/decryption context placeholder.
pub struct AesCbcContext;

/// AES-CBC key operations placeholder.
pub struct AesCbcKey;

#[cfg(test)]
mod test {
    //! # AES-CBC Test Suite
    //!
    //! This module contains comprehensive tests for AES-CBC encryption and decryption, including single-shot and streaming (update/final) APIs, key import/export, padding, IV handling, and error conditions.
    //!
    //! ## Test Vector Source
    //!
    //!  test vectors in test_nist_matrix_aes_cbc_encrypt_decrypt are taken from NIST SP 800-38A F.2 section:
    //! <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf>
    //!
    //! These vectors ensure compatibility with the NIST specification for AES-CBC mode.
    //! test vectors in test_aes_cbc_encrypt_decrypt_matrix_pkcs7_vectors are derived using openssl command
    //! to validate the PKCS#7 padding
    //!
    //! ## Test Coverage
    //!
    //! - Randomized roundtrip encryption/decryption for all AES key sizes (128, 192, 256 bits).
    //! - Single-shot and streaming (update/final) APIs for both encryption and decryption.
    //! - Handling of empty, small, large, and non-UTF8 data.
    //! - All possible chunkings and cross-chunk boundary conditions for streaming APIs.
    //! - PKCS#7 padding correctness and edge cases.
    //! - IV uniqueness, reuse, and length validation.
    //! - Key import from bytes and slices, including invalid key lengths.
    //! - Error handling for corrupted ciphertext, wrong key/IV, and invalid parameters.
    //! - Interleaved context usage and repeated finalization safety.
    //! - Verification against NIST and OpenSSL test vectors for correctness.
    //!
    //! These tests are intended to provide high confidence in the correctness, robustness, and interoperability of the AES-CBC implementation.
    use rand::Rng;
    use test_log::test;

    use super::*;

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen()).collect()
    }

    #[test]
    fn test_aes_cbc_encrypt_with_random_key_and_iv() {
        let key_op = AesCbcKey;
        let key = key_op
            .aes_cbc_generate_key(AesKeySize::Aes256)
            .expect("Key generation failed");
        let data = b"Test data for AES CBC encryption";
        let iv = random_bytes(16);
        let result = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .expect("Encryption failed");
        assert!(
            !result.cipher_text.is_empty(),
            "Cipher text should not be empty"
        );
        assert_eq!(result.iv.len(), 16, "IV should be 16 bytes");
    }

    #[test]
    fn test_simple_encrypt_decrypt_with_traits() {
        // Use AesCbcKey as the key generator and implementor of the traits
        let key_op = AesCbcKey;
        // Generate a 128-bit AES key
        let key = key_op
            .aes_cbc_generate_key(AesKeySize::Aes128)
            .expect("Key generation failed");
        let plaintext = b"Hello AES CBC!";
        // Encrypt using the trait
        let encrypt_result = key
            .aes_cbc_encrypt(plaintext, None, Some(AesCbcPadding::Pkcs7))
            .expect("Encryption failed");
        assert!(
            !encrypt_result.cipher_text.is_empty(),
            "Ciphertext should not be empty"
        );
        assert!(
            !encrypt_result.iv.is_empty(),
            "IV should be present in encryption result"
        );
        // Decrypt using the trait
        let decrypt_result = key
            .aes_cbc_decrypt(
                &encrypt_result.cipher_text,
                &encrypt_result.iv,
                Some(AesCbcPadding::Pkcs7),
            )
            .expect("Decryption failed");
        assert_eq!(
            decrypt_result.plain_text, plaintext,
            "Decrypted text should match original"
        );
    }

    #[test]
    fn test_encrypt_decrypt_with_update_and_final() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let data = b"Chunked CBC encryption and decryption test data!";
        // Generate IV (AES block size is 16)
        let mut iv = vec![0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);
        // Encrypt in chunks using update/final
        let mut encrypter = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        encrypter.aes_cbc_encrypt_update(&data[..10]).unwrap();
        encrypter.aes_cbc_encrypt_update(&data[10..30]).unwrap();
        encrypter.aes_cbc_encrypt_update(&data[30..]).unwrap();
        let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
        let cipher_text = &enc_result.cipher_text;
        // Decrypt in chunks using update/final, using the same IV as encryption
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        // Feed the ciphertext in two chunks
        let mid = cipher_text.len() / 2;
        decrypter
            .aes_cbc_decrypt_update(&cipher_text[..mid])
            .unwrap();
        decrypter
            .aes_cbc_decrypt_update(&cipher_text[mid..])
            .unwrap();
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(pt, data, "Decrypted data should match original");
    }

    #[test]
    fn test_encrypt_decrypt_update_final_empty_data() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let data = b"";
        let mut iv = vec![0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        // Encrypt empty data
        let mut encrypter = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        encrypter.aes_cbc_encrypt_update(data).unwrap();
        let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
        let cipher_text = &enc_result.cipher_text;

        // Decrypt empty data using the same IV as encryption
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        decrypter.aes_cbc_decrypt_update(cipher_text).unwrap();
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert!(
            pt.is_empty(),
            "Decrypted output should be empty for empty input"
        );
        assert_eq!(pt, data, "Decrypted empty data should match original");
    }

    #[test]
    fn test_encrypt_decrypt_update_final_large_data() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let data = random_bytes(4096);
        let mut iv = vec![0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        // Encrypt in chunks
        let mut encrypter = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let chunk_size = 1024;
        for chunk in data.chunks(chunk_size) {
            encrypter.aes_cbc_encrypt_update(chunk).unwrap();
        }
        let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
        let cipher_text = &enc_result.cipher_text;

        // Decrypt in chunks
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        for chunk in cipher_text.chunks(chunk_size) {
            decrypter.aes_cbc_decrypt_update(chunk).unwrap();
        }
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(pt, &data, "Decrypted large data should match original");
    }

    #[test]
    fn test_aes_cbc_encrypt_with_empty_data() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let data = b"";
        let result = key
            .aes_cbc_encrypt(data, None, Some(AesCbcPadding::Pkcs7))
            .expect("Encryption failed");
        assert!(
            !result.cipher_text.is_empty(),
            "Ciphertext should not be empty"
        );
    }

    #[test]
    fn test_aes_cbc_encrypt_different_ivs_produce_different_ciphertext() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let data = b"Test data for IV difference";
        let iv1 = random_bytes(16);
        let iv2 = random_bytes(16);
        let ct1 = key
            .aes_cbc_encrypt(data, Some(&iv1), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let ct2 = key
            .aes_cbc_encrypt(data, Some(&iv2), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        assert_ne!(
            ct1.cipher_text, ct2.cipher_text,
            "Ciphertexts should differ for different IVs"
        );
    }

    #[test]
    fn test_aes_cbc_encrypt_same_iv_same_key_same_plaintext() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let data = b"Test data for deterministic CBC";
        let iv = random_bytes(16);
        let ct1 = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let ct2 = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        assert_eq!(
            ct1.cipher_text, ct2.cipher_text,
            "Ciphertexts should match for same IV, key, and plaintext"
        );
    }

    #[test]
    fn test_aes_cbc_from_bytes_single_shot() {
        // 256-bit key (32 bytes)
        let key_bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let iv = vec![
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        let plaintext = b"from_vec and from_slice test data!";

        let key_vec = AesCbcKey::from_slice(&key_bytes).expect("from_slice failed");
        let enc_result_vec = key_vec
            .aes_cbc_encrypt(plaintext, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .expect("encryption failed");
        let dec_result_vec = key_vec
            .aes_cbc_decrypt(
                &enc_result_vec.cipher_text,
                &enc_result_vec.iv,
                Some(AesCbcPadding::Pkcs7),
            )
            .expect("decryption failed");
        assert_eq!(dec_result_vec.plain_text, plaintext);
    }

    #[test]
    fn test_aes_cbc_from_slice_single_shot() {
        // 256-bit key (32 bytes)
        let key_bytes = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let iv = vec![
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        let plaintext = b"from_vec and from_slice test data!";

        let key_slice = AesCbcKey::from_slice(&key_bytes).expect("from_slice failed");
        let enc_result_slice = key_slice
            .aes_cbc_encrypt(plaintext, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .expect("encryption failed");
        let dec_result_slice = key_slice
            .aes_cbc_decrypt(
                &enc_result_slice.cipher_text,
                &enc_result_slice.iv,
                Some(AesCbcPadding::Pkcs7),
            )
            .expect("decryption failed");
        assert_eq!(dec_result_slice.plain_text, plaintext);
    }

    #[test]
    fn test_aes_cbc_from_bytes_update_final() {
        let key_bytes = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
            0xD0, 0xE0, 0xF0, 0x01,
        ];
        let iv = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
            0xDC, 0xFE,
        ];
        let data = b"update/final test for from_vec and from_slice trait impls!";

        let key_vec = AesCbcKey::from_slice(&key_bytes).expect("from_slice failed");
        let mut encrypter_vec = key_vec
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .expect("init cypher failed");
        encrypter_vec.aes_cbc_encrypt_update(&data[..10]).unwrap();
        encrypter_vec.aes_cbc_encrypt_update(&data[10..30]).unwrap();
        encrypter_vec.aes_cbc_encrypt_update(&data[30..]).unwrap();
        let enc_result_vec = encrypter_vec.aes_cbc_encrypt_final().unwrap();
        let cipher_text_vec = &enc_result_vec.cipher_text;

        let mut decrypter_vec = key_vec
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let mid = cipher_text_vec.len() / 2;
        decrypter_vec
            .aes_cbc_decrypt_update(&cipher_text_vec[..mid])
            .unwrap();
        decrypter_vec
            .aes_cbc_decrypt_update(&cipher_text_vec[mid..])
            .unwrap();
        let dec_result_vec = decrypter_vec.aes_cbc_decrypt_final().unwrap();
        let pt_vec = &dec_result_vec.plain_text;
        assert_eq!(pt_vec, data);
    }

    #[test]
    fn test_aes_cbc_from_slice_update_final() {
        let key_bytes = vec![
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
            0xD0, 0xE0, 0xF0, 0x01,
        ];
        let iv = vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA,
            0xDC, 0xFE,
        ];
        let data = b"update/final test for from_vec and from_slice trait impls!";

        let key_slice = AesCbcKey::from_slice(&key_bytes).expect("from_slice failed");
        let mut encrypter_slice = key_slice
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .expect("init cypher failed");
        encrypter_slice.aes_cbc_encrypt_update(&data[..15]).unwrap();
        encrypter_slice.aes_cbc_encrypt_update(&data[15..]).unwrap();
        let enc_result_slice = encrypter_slice.aes_cbc_encrypt_final().unwrap();
        let cipher_text_slice = &enc_result_slice.cipher_text;

        let mut decrypter_slice = key_slice
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        decrypter_slice
            .aes_cbc_decrypt_update(cipher_text_slice)
            .unwrap();
        let dec_result_slice = decrypter_slice.aes_cbc_decrypt_final().unwrap();
        let pt_slice = &dec_result_slice.plain_text;
        assert_eq!(pt_slice, data);
    }

    #[test]
    fn test_aes_cbc_randomized_stress() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let mut rng = rand::thread_rng();
        for &size in &[0, 1, 15, 16, 17, 31, 32, 100, 1024, 4096, 16384] {
            let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let iv = random_bytes(16);
            let enc = key
                .aes_cbc_encrypt(&data, Some(&iv), Some(AesCbcPadding::Pkcs7))
                .unwrap();
            let dec = key
                .aes_cbc_decrypt(&enc.cipher_text, &enc.iv, Some(AesCbcPadding::Pkcs7))
                .unwrap();
            assert_eq!(dec.plain_text, data, "Failed for size {size}");
        }
    }

    #[test]
    fn test_aes_cbc_all_zero_and_ff() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        for &byte in &[0u8, 0xFF] {
            let data = vec![byte; 128];
            let enc = key
                .aes_cbc_encrypt(&data, Some(&iv), Some(AesCbcPadding::Pkcs7))
                .unwrap();
            let dec = key
                .aes_cbc_decrypt(&enc.cipher_text, &enc.iv, Some(AesCbcPadding::Pkcs7))
                .unwrap();
            assert_eq!(dec.plain_text, data, "Failed for byte value {byte}");
        }
    }

    #[test]
    fn test_aes_cbc_iv_reuse() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data = b"Sensitive data block";
        let enc1 = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let enc2 = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        assert_eq!(
            enc1.cipher_text, enc2.cipher_text,
            "Ciphertext should match for same key/IV/data"
        );
    }

    #[test]
    fn test_aes_cbc_corrupted_ciphertext() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data = b"Corruption test block";
        let enc = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let mut corrupted = enc.cipher_text.clone();
        corrupted[0] ^= 0xFF; // Flip a bit
        let dec = key.aes_cbc_decrypt(&corrupted, enc.iv.as_slice(), Some(AesCbcPadding::Pkcs7));
        assert!(
            dec.is_err() || dec.unwrap().plain_text != data,
            "Corrupted ciphertext should not decrypt correctly"
        );
    }

    #[test]
    fn test_aes_cbc_padding_edge_cases() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        for &size in &[15, 16, 17, 31, 32, 33] {
            let data = vec![0xAB; size];
            let enc = key
                .aes_cbc_encrypt(&data, Some(&iv), Some(AesCbcPadding::Pkcs7))
                .unwrap();
            let dec = key
                .aes_cbc_decrypt(
                    &enc.cipher_text,
                    enc.iv.as_slice(),
                    Some(AesCbcPadding::Pkcs7),
                )
                .unwrap();
            assert_eq!(dec.plain_text, data, "Failed for edge size {size}");
        }
    }

    #[test]
    fn test_aes_cbc_update_final_chunked_stress() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let mut rng = rand::thread_rng();
        for &size in &[0, 1, 15, 16, 17, 31, 32, 100, 1024, 4096, 16384] {
            let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();
            let iv = random_bytes(16);
            // Try different chunk sizes for update
            for &chunk_size in &[1, 2, 7, 16, 31, 32, 64, 128, 256, 512, 1024] {
                let mut encrypter = key
                    .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
                    .unwrap();
                for chunk in data.chunks(chunk_size) {
                    encrypter.aes_cbc_encrypt_update(chunk).unwrap();
                }
                let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
                let cipher_text = &enc_result.cipher_text;

                // Decrypt in different chunk sizes as well
                for &dec_chunk_size in &[1, 2, 7, 16, 31, 32, 64, 128, 256, 512, 1024] {
                    let mut decrypter = key
                        .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
                        .unwrap();
                    for chunk in cipher_text.chunks(dec_chunk_size) {
                        decrypter.aes_cbc_decrypt_update(chunk).unwrap();
                    }
                    let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
                    let pt = &dec_result.plain_text;
                    assert_eq!(
                        pt.as_slice(),
                        data.as_slice(),
                        "Chunked update/final failed for size {size}, enc_chunk {chunk_size}, dec_chunk {dec_chunk_size}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_aes_cbc_cross_chunk_boundary_padding() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        // Data size not a multiple of block size (e.g., 23 bytes, block size is 16)
        let data = vec![0x42; 23];
        // Try all possible chunk splits
        for split in 1..data.len() {
            let mut encrypter = key
                .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
                .unwrap();
            encrypter.aes_cbc_encrypt_update(&data[..split]).unwrap();
            encrypter.aes_cbc_encrypt_update(&data[split..]).unwrap();
            let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
            let cipher_text = &enc_result.cipher_text;
            // Decrypt in one go
            let mut decrypter = key
                .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
                .unwrap();
            decrypter.aes_cbc_decrypt_update(cipher_text).unwrap();
            let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
            let pt = &dec_result.plain_text;
            assert_eq!(
                pt.as_slice(),
                data.as_slice(),
                "Cross-chunk boundary failed at split {split}"
            );
        }
    }

    #[test]
    fn test_aes_cbc_all_possible_chunkings() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data = b"ABCDEFGH12345678"; // 16 bytes
                                        // Try all possible chunkings (for small data)
        for split1 in 1..data.len() {
            for split2 in split1 + 1..=data.len() {
                let mut encrypter = key
                    .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
                    .unwrap();
                encrypter.aes_cbc_encrypt_update(&data[..split1]).unwrap();
                encrypter
                    .aes_cbc_encrypt_update(&data[split1..split2])
                    .unwrap();
                encrypter.aes_cbc_encrypt_update(&data[split2..]).unwrap();
                let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
                let cipher_text = &enc_result.cipher_text;
                // Decrypt in one go
                let mut decrypter = key
                    .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
                    .unwrap();
                decrypter.aes_cbc_decrypt_update(cipher_text).unwrap();
                let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
                let pt = &dec_result.plain_text;
                assert_eq!(
                    pt, data,
                    "All chunkings failed at splits {split1}, {split2}"
                );
            }
        }
    }

    #[test]
    fn test_aes_cbc_interleaved_contexts() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv1 = random_bytes(16);
        let iv2 = random_bytes(16);
        let data1 = b"Interleaved context 1";
        let data2 = b"Interleaved context 2, longer!";
        let mut enc1 = key
            .aes_cbc_encrypt_init(Some(iv1.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let mut enc2 = key
            .aes_cbc_encrypt_init(Some(iv2.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        // Interleave updates
        enc1.aes_cbc_encrypt_update(&data1[..10]).unwrap();
        enc2.aes_cbc_encrypt_update(&data2[..10]).unwrap();
        enc1.aes_cbc_encrypt_update(&data1[10..]).unwrap();
        enc2.aes_cbc_encrypt_update(&data2[10..]).unwrap();
        let enc_result1 = enc1.aes_cbc_encrypt_final().unwrap();
        let enc_result2 = enc2.aes_cbc_encrypt_final().unwrap();
        let ct1 = &enc_result1.cipher_text;
        let ct2 = &enc_result2.cipher_text;
        // Decrypt
        let mut dec1 = key
            .aes_cbc_decrypt_init(iv1.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let mut dec2 = key
            .aes_cbc_decrypt_init(iv2.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        dec1.aes_cbc_decrypt_update(ct1).unwrap();
        dec2.aes_cbc_decrypt_update(ct2).unwrap();
        let dec_result1 = dec1.aes_cbc_decrypt_final().unwrap();
        let dec_result2 = dec2.aes_cbc_decrypt_final().unwrap();
        assert_eq!(
            &dec_result1.plain_text[..],
            data1,
            "Interleaved context 1 failed"
        );
        assert_eq!(
            &dec_result2.plain_text[..],
            data2,
            "Interleaved context 2 failed"
        );
    }

    #[test]
    fn test_aes_cbc_decrypt_with_wrong_key_or_iv() {
        let key_op = AesCbcKey;
        let key1 = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let key2 = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data = b"Decrypt with wrong key or IV!";
        let enc = key1
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        // Decrypt with wrong key
        let dec_wrong_key = key2.aes_cbc_decrypt(
            &enc.cipher_text,
            enc.iv.as_slice(),
            Some(AesCbcPadding::Pkcs7),
        );
        // Decrypt with wrong IV
        let wrong_iv = random_bytes(16);
        let dec_wrong_iv =
            key1.aes_cbc_decrypt(&enc.cipher_text, &wrong_iv, Some(AesCbcPadding::Pkcs7));
        assert!(
            dec_wrong_key.is_err() || dec_wrong_key.as_ref().unwrap().plain_text != data,
            "Decryption with wrong key should fail or produce wrong output"
        );
        assert!(
            dec_wrong_iv.is_err() || dec_wrong_iv.as_ref().unwrap().plain_text != data,
            "Decryption with wrong IV should fail or produce wrong output"
        );
    }

    #[test]
    fn test_single_shot_encrypt_streaming_decrypt() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let data = b"Single-shot encrypt, streaming decrypt test data!";
        let iv = random_bytes(16);
        // Single-shot encryption
        let enc_result = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let cipher_text = &enc_result.cipher_text;
        // Streaming decryption
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        for chunk in cipher_text.chunks(7) {
            decrypter.aes_cbc_decrypt_update(chunk).unwrap();
        }
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(
            pt.as_slice(),
            data.as_slice(),
            "Single-shot encrypt, streaming decrypt failed"
        );
    }

    #[test]
    fn test_streaming_encrypt_single_shot_decrypt() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let data = b"Streaming encrypt, single-shot decrypt test data!";
        let iv = random_bytes(16);
        // Streaming encryption
        let mut encrypter = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        for chunk in data.chunks(5) {
            encrypter.aes_cbc_encrypt_update(chunk).unwrap();
        }
        let enc_result = encrypter.aes_cbc_encrypt_final().unwrap();
        let cipher_text = &enc_result.cipher_text;
        // Single-shot decryption
        let dec_result = key
            .aes_cbc_decrypt(cipher_text, &iv, Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(
            pt.as_slice(),
            data.as_slice(),
            "Streaming encrypt, single-shot decrypt failed"
        );
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt_with_all_zero_iv() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let data = b"Test data for all-zero IV";
        let iv = vec![0u8; 16];
        // Encrypt with all-zero IV
        let enc_result = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let cipher_text = &enc_result.cipher_text;
        // Decrypt with all-zero IV
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        decrypter.aes_cbc_decrypt_update(cipher_text).unwrap();
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(
            pt.as_slice(),
            data.as_slice(),
            "AES-CBC all-zero IV roundtrip failed"
        );
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt_aes192() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes192).unwrap();
        let data = b"Test data for AES-192 key size!";
        let iv = random_bytes(16);
        // Encrypt with AES-192
        let enc_result = key
            .aes_cbc_encrypt(data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let cipher_text = &enc_result.cipher_text;
        // Decrypt with AES-192
        let mut decrypter = key
            .aes_cbc_decrypt_init(iv.as_slice(), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        decrypter.aes_cbc_decrypt_update(cipher_text).unwrap();
        let dec_result = decrypter.aes_cbc_decrypt_final().unwrap();
        let pt = &dec_result.plain_text;
        assert_eq!(
            pt.as_slice(),
            data.as_slice(),
            "AES-CBC AES-192 roundtrip failed"
        );
    }

    #[test]
    fn test_aes_cbc_iv_length_mismatch() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let data = b"Test IV length mismatch";
        let short_iv = vec![0u8; 15];
        let long_iv = vec![0u8; 17];
        assert!(
            key.aes_cbc_encrypt(data, Some(&short_iv), Some(AesCbcPadding::Pkcs7))
                .is_err(),
            "Short IV should fail"
        );
        assert!(
            key.aes_cbc_encrypt(data, Some(&long_iv), Some(AesCbcPadding::Pkcs7))
                .is_err(),
            "Long IV should fail"
        );
        assert!(
            key.aes_cbc_decrypt(data, &short_iv, Some(AesCbcPadding::Pkcs7))
                .is_err(),
            "Short IV should fail for decrypt"
        );
        assert!(
            key.aes_cbc_decrypt(data, &long_iv, Some(AesCbcPadding::Pkcs7))
                .is_err(),
            "Long IV should fail for decrypt"
        );
    }

    #[test]
    fn test_aes_cbc_key_length_mismatch() {
        let bad_key_15 = vec![0u8; 15];
        let bad_key_33 = vec![0u8; 33];
        assert!(
            AesCbcKey::from_slice(&bad_key_15).is_err(),
            "15-byte key should fail"
        );
        assert!(
            AesCbcKey::from_slice(&bad_key_33).is_err(),
            "33-byte key should fail"
        );
    }

    #[test]
    fn test_aes_cbc_non_utf8_plaintext() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data: Vec<u8> = (0..=255).collect(); // All byte values
        let enc = key
            .aes_cbc_encrypt(&data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let dec = key
            .aes_cbc_decrypt(
                &enc.cipher_text,
                enc.iv.as_slice(),
                Some(AesCbcPadding::Pkcs7),
            )
            .unwrap();
        assert_eq!(dec.plain_text, data, "Non-UTF8 roundtrip failed");
    }

    #[test]
    fn test_aes_cbc_repeated_finalization() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes128).unwrap();
        let iv = random_bytes(16);
        let data = b"Repeated finalization";
        let mut encrypter = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        encrypter.aes_cbc_encrypt_update(data).unwrap();
        let _ = encrypter.aes_cbc_encrypt_final().unwrap();
        // In Rust, after finalization, the encrypter is moved and cannot be used again.
        // Attempting to call aes_cbc_encrypt_final() again on the same instance is a compile-time error.
        // This test documents that double-finalization is prevented by Rust's ownership system.
        // If you want to test error on double-finalization, you must use a new context instance.
        let mut encrypter2 = key
            .aes_cbc_encrypt_init(Some(iv.as_slice()), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        encrypter2.aes_cbc_encrypt_update(data).unwrap();
        let _ = encrypter2.aes_cbc_encrypt_final().unwrap();
        // The following would not compile:
        // let _ = encrypter2.aes_cbc_encrypt_final();
    }

    #[test]
    fn test_aes_cbc_very_large_data() {
        let key_op = AesCbcKey;
        let key = key_op.aes_cbc_generate_key(AesKeySize::Aes256).unwrap();
        let iv = random_bytes(16);
        let data = vec![0xAB; 1024 * 1024]; // 1MB
        let enc = key
            .aes_cbc_encrypt(&data, Some(&iv), Some(AesCbcPadding::Pkcs7))
            .unwrap();
        let dec = key
            .aes_cbc_decrypt(
                &enc.cipher_text,
                enc.iv.as_slice(),
                Some(AesCbcPadding::Pkcs7),
            )
            .unwrap();
        assert_eq!(dec.plain_text, data, "Very large data roundtrip failed");
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt_matrix_pkcs7_vectors() {
        // Matrix test: 3 key sizes × 3 plaintext lengths (15, 16, 17 bytes)
        // All vectors generated with OpenSSL using PKCS#7 padding
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        // Test vector arrays
        const PLAINTEXT_128_15: [u8; 15] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17,
        ];
        const CIPHERTEXT_128_15: [u8; 16] = [
            0xf5, 0xe5, 0xc8, 0xf1, 0xe9, 0x45, 0x28, 0x61, 0xe5, 0xbd, 0x96, 0xab, 0x85, 0xec,
            0xc2, 0xef,
        ];
        const PLAINTEXT_128_16: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f,
        ];
        const CIPHERTEXT_128_16: [u8; 32] = [
            0x60, 0x53, 0x60, 0x80, 0xcc, 0x63, 0x4e, 0x94, 0x14, 0x6f, 0x7f, 0x18, 0xbd, 0xfa,
            0x2e, 0xc6, 0x79, 0xd8, 0x0b, 0xe9, 0x35, 0xf7, 0x72, 0x81, 0x9f, 0x7e, 0xd9, 0xbf,
            0xf3, 0xb5, 0x11, 0x0f,
        ];
        const PLAINTEXT_128_17: [u8; 17] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f, 0x11,
        ];
        const CIPHERTEXT_128_17: [u8; 32] = [
            0x60, 0x53, 0x60, 0x80, 0xcc, 0x63, 0x4e, 0x94, 0x14, 0x6f, 0x7f, 0x18, 0xbd, 0xfa,
            0x2e, 0xc6, 0x11, 0x22, 0x8d, 0xb2, 0x3f, 0x45, 0xa5, 0xdc, 0x66, 0x07, 0xc1, 0xe3,
            0xb9, 0x77, 0x60, 0x5d,
        ];
        const PLAINTEXT_192_15: [u8; 15] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17,
        ];
        const CIPHERTEXT_192_15: [u8; 16] = [
            0x67, 0xa1, 0x75, 0x76, 0xb9, 0xb1, 0x5f, 0x90, 0xc5, 0x40, 0xf5, 0x72, 0xae, 0x5e,
            0xf8, 0x3b,
        ];
        const PLAINTEXT_192_16: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f,
        ];
        const CIPHERTEXT_192_16: [u8; 32] = [
            0x54, 0x17, 0x8b, 0xd6, 0xf4, 0xb9, 0xbd, 0xf2, 0x39, 0x5b, 0xd8, 0x77, 0x37, 0x72,
            0xd1, 0x77, 0xfe, 0x98, 0xd6, 0x9d, 0x73, 0x3c, 0xd6, 0x1b, 0xb8, 0x08, 0x16, 0x40,
            0x84, 0xc9, 0x98, 0xc1,
        ];
        const PLAINTEXT_192_17: [u8; 17] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f, 0x11,
        ];
        const CIPHERTEXT_192_17: [u8; 32] = [
            0x54, 0x17, 0x8b, 0xd6, 0xf4, 0xb9, 0xbd, 0xf2, 0x39, 0x5b, 0xd8, 0x77, 0x37, 0x72,
            0xd1, 0x77, 0x01, 0xc7, 0x1b, 0xf4, 0xff, 0x51, 0xeb, 0x23, 0xd2, 0x3f, 0xd4, 0xd2,
            0x3a, 0xb2, 0x92, 0x3a,
        ];
        const PLAINTEXT_256_15: [u8; 15] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17,
        ];
        const CIPHERTEXT_256_15: [u8; 16] = [
            0x29, 0x59, 0x02, 0xe1, 0x55, 0x59, 0xd5, 0x91, 0xff, 0xbe, 0xea, 0x4c, 0x84, 0x05,
            0x92, 0x80,
        ];
        const PLAINTEXT_256_16: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f,
        ];
        const CIPHERTEXT_256_16: [u8; 32] = [
            0x9c, 0x2f, 0x26, 0x0c, 0x78, 0xc9, 0x4c, 0xff, 0xe4, 0x8b, 0x7f, 0x78, 0xcc, 0x77,
            0xcf, 0xac, 0x35, 0xfa, 0x3b, 0x54, 0xd1, 0x9f, 0x29, 0x11, 0x9d, 0x86, 0x14, 0xdc,
            0x74, 0x81, 0xba, 0xe8,
        ];
        const PLAINTEXT_256_17: [u8; 17] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x0f, 0x11,
        ];
        const CIPHERTEXT_256_17: [u8; 32] = [
            0x9c, 0x2f, 0x26, 0x0c, 0x78, 0xc9, 0x4c, 0xff, 0xe4, 0x8b, 0x7f, 0x78, 0xcc, 0x77,
            0xcf, 0xac, 0xd4, 0x7a, 0x11, 0xf1, 0x81, 0xef, 0xe0, 0x78, 0x61, 0x78, 0x35, 0x32,
            0x00, 0xd9, 0xd1, 0xfa,
        ];

        let test_cases = [
            // 128-bit key
            (
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x09, 0x35, 0x6c,
                    0x3f, 0x7c, 0x7a,
                ][..],
                &PLAINTEXT_128_15[..],
                &CIPHERTEXT_128_15[..],
            ),
            (
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x09, 0x35, 0x6c,
                    0x3f, 0x7c, 0x7a,
                ][..],
                &PLAINTEXT_128_16[..],
                &CIPHERTEXT_128_16[..],
            ),
            (
                &[
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x09, 0x35, 0x6c,
                    0x3f, 0x7c, 0x7a,
                ][..],
                &PLAINTEXT_128_17[..],
                &CIPHERTEXT_128_17[..],
            ),
            // 192-bit key
            (
                &[
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80,
                    0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                ][..],
                &PLAINTEXT_192_15[..],
                &CIPHERTEXT_192_15[..],
            ),
            (
                &[
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80,
                    0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                ][..],
                &PLAINTEXT_192_16[..],
                &CIPHERTEXT_192_16[..],
            ),
            (
                &[
                    0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80,
                    0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
                ][..],
                &PLAINTEXT_192_17[..],
                &CIPHERTEXT_192_17[..],
            ),
            // 256-bit key
            (
                &[
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ][..],
                &PLAINTEXT_256_15[..],
                &CIPHERTEXT_256_15[..],
            ),
            (
                &[
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ][..],
                &PLAINTEXT_256_16[..],
                &CIPHERTEXT_256_16[..],
            ),
            (
                &[
                    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
                    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
                    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                ][..],
                &PLAINTEXT_256_17[..],
                &CIPHERTEXT_256_17[..],
            ),
        ];
        for (key, plaintext, expected_ciphertext) in test_cases.iter() {
            let key_obj = AesCbcKey::from_slice(key).expect("Key import failed");
            let result = key_obj
                .aes_cbc_encrypt(plaintext, Some(&iv), Some(AesCbcPadding::Pkcs7))
                .expect("Encryption failed");
            assert_eq!(
                &result.cipher_text[..expected_ciphertext.len()],
                *expected_ciphertext,
                "Ciphertext does not match OpenSSL PKCS#7 vector (matrix)"
            );
            let dec = key_obj
                .aes_cbc_decrypt(&result.cipher_text, &iv, Some(AesCbcPadding::Pkcs7))
                .expect("Decryption failed");
            assert_eq!(
                &dec.plain_text[..plaintext.len()],
                *plaintext,
                "Decrypted plaintext does not match original (matrix)"
            );
        }
    }

    #[test]
    fn test_nist_aes128_cbc_encrypt_decrypt_blocks() {
        // NIST SP 800-38A F.2.1 CBC-AES128 test vector
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        let expected_ciphertext = [
            0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9,
            0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a,
            0x91, 0x76, 0x78, 0xb2, 0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16,
            0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
            0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
        ];
        let key_obj = AesCbcKey::from_slice(&key).unwrap();
        let enc = key_obj
            .aes_cbc_encrypt(&plaintext, Some(&iv), None)
            .unwrap();
        assert_eq!(
            enc.cipher_text, expected_ciphertext,
            "AES-128 CBC NIST vector encryption"
        );
        let dec = key_obj
            .aes_cbc_decrypt(&expected_ciphertext, &iv, None)
            .unwrap();
        assert_eq!(
            dec.plain_text, plaintext,
            "AES-128 CBC NIST vector decryption"
        );
    }

    #[test]
    fn test_nist_matrix_aes_cbc_encrypt_decrypt() {
        struct TestVector {
            key: &'static [u8],
            iv: &'static [u8],
            plaintext: &'static [&'static [u8]],
            ciphertext: &'static [&'static [u8]],
        }
        // AES-128
        let tv128 = TestVector {
            key: &{
                [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ]
            },
            iv: &{
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ]
            },
            plaintext: &[
                &[
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ],
                &[
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                    0xaf, 0x8e, 0x51,
                ],
                &[
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                    0x0a, 0x52, 0xef,
                ],
                &[
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                    0x6c, 0x37, 0x10,
                ],
            ],
            ciphertext: &[
                &[
                    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12,
                    0xe9, 0x19, 0x7d,
                ],
                &[
                    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91,
                    0x76, 0x78, 0xb2,
                ],
                &[
                    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22,
                    0x22, 0x95, 0x16,
                ],
                &[
                    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75,
                    0x86, 0xe1, 0xa7,
                ],
            ],
        };
        // Test encryption (block by block, chaining IV)
        let key_obj = AesCbcKey::from_slice(tv128.key).unwrap();
        let mut prev = tv128.iv.to_vec();
        let mut ciphertext = Vec::new();
        for (i, pt) in tv128.plaintext.iter().enumerate() {
            let enc = key_obj.aes_cbc_encrypt(pt, Some(&prev), None).unwrap();
            assert_eq!(
                enc.cipher_text,
                tv128.ciphertext[i],
                "AES-128 CBC NIST block {} encryption",
                i + 1
            );
            ciphertext.extend_from_slice(&enc.cipher_text);
            prev = enc.cipher_text.clone();
        }
        // Test decryption (block by block, chaining IV)
        let mut prev = tv128.iv.to_vec();
        for (i, ct) in tv128.ciphertext.iter().enumerate() {
            let dec = key_obj.aes_cbc_decrypt(ct, &prev, None).unwrap();
            assert_eq!(
                dec.plain_text,
                tv128.plaintext[i],
                "AES-128 CBC NIST block {} decryption",
                i + 1
            );
            prev = ct.to_vec();
        }
    }
}
