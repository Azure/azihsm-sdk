// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based AES key implementation for Linux platforms.
//!
//! This module provides AES key management using OpenSSL's cryptographic primitives.
//! It supports AES-128, AES-192, and AES-256 key sizes with CBC mode cipher operations.

use super::*;

/// OpenSSL-backed AES key implementation.
///
/// This structure wraps an AES key along with its corresponding OpenSSL cipher
/// configuration. It stores the raw key bytes and maintains a reference to the
/// appropriate cipher (AES-128-CBC, AES-192-CBC, or AES-256-CBC) based on key size.
///
/// # Key Sizes
///
/// - 16 bytes (128 bits) - AES-128
/// - 24 bytes (192 bits) - AES-192
/// - 32 bytes (256 bits) - AES-256
///
/// # Security
///
/// The key material is stored in a `Vec<u8>` which should be properly zeroized
/// when dropped to prevent key material from remaining in memory.
#[derive(Clone)]
pub struct OsslAesKey {
    /// Raw key bytes
    key: Vec<u8>,
}

/// Marks this type as a cryptographic key.
///
/// This implementation designates `OsslAesKey` as a valid cryptographic key
/// type in the library's type system, enabling its use with key management
/// operations.
impl Key for OsslAesKey {
    /// Returns the length of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
    fn size(&self) -> usize {
        self.key.len()
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.key.len() * 8
    }
}

/// Marks this key as suitable for encryption operations.
///
/// This implementation enables `OsslAesKey` to be used with encryption
/// operations such as AES-CBC encryption.
impl EncryptionKey for OsslAesKey {}

/// Marks this key as suitable for decryption operations.
///
/// This implementation enables `OsslAesKey` to be used with decryption
/// operations such as AES-CBC decryption.
impl DecryptionKey for OsslAesKey {}

/// Marks this key as containing secret material.
///
/// This implementation indicates that `OsslAesKey` contains sensitive
/// cryptographic material that must be protected and handled securely.
impl SecretKey for OsslAesKey {}

/// Marks this key as suitable for key wrapping operations.
///
/// This implementation enables `OsslAesKey` to be used for wrapping
/// (encrypting) other cryptographic keys using AES key wrap algorithms.
impl WrappingKey for OsslAesKey {}

/// Marks this key as suitable for key unwrapping operations.
///
/// This implementation enables `OsslAesKey` to be used for unwrapping
/// (decrypting) other cryptographic keys using AES key wrap algorithms.
impl UnwrappingKey for OsslAesKey {}

/// Provides symmetric key operations for AES keys.
impl SymmetricKey for OsslAesKey {}

/// Marks this key as importable.
///
/// This implementation enables `OsslAesKey` to be created from bytes
/// in key unwrapping operations.
impl ImportableKey for OsslAesKey {
    /// Creates an AES key from raw byte data.
    ///
    /// This method validates the key size and creates the appropriate cipher
    /// configuration (AES-128, AES-192, or AES-256) based on the input length.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key material (must be 16, 24, or 32 bytes)
    ///
    /// # Returns
    ///
    /// A new `OsslAesKey` instance configured with the appropriate cipher.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the key size is not 16, 24, or 32 bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Self::validate_key_size(bytes.len())?;
        Ok(OsslAesKey::new(bytes))
    }
}

/// Marks this key as exportable.
///
/// This implementation enables `OsslAesKey` to be used in key wrapping
/// operations that require exporting the key to bytes.
impl ExportableKey for OsslAesKey {
    /// Exports the AES key to a byte buffer.
    ///
    /// This method can either return the required buffer size (when `bytes` is `None`)
    /// or copy the key material to the provided buffer (when `bytes` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer for the key material
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesBufferTooSmall` if the provided buffer is too small.
    ///
    /// # Security Warning
    ///
    /// The exported key material should be handled with care:
    /// - Clear the buffer after use to prevent key leakage
    /// - Encrypt the key before storage or transmission
    /// - Use secure channels for key transport
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let key_len = self.key.len();
        if let Some(bytes) = bytes {
            if bytes.len() < key_len {
                Err(CryptoError::AesBufferTooSmall)?;
            }
            bytes[..key_len].copy_from_slice(&self.key);
        }
        Ok(key_len)
    }
}

impl KeyGenerationOp for OsslAesKey {
    type Key = Self;

    /// Generates a new AES key with cryptographically secure random data.
    ///
    /// This method creates a new AES key of the specified size (16, 24, or 32 bytes)
    /// using OpenSSL's secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `size` - Desired key size in bytes (16, 24, or 32)
    ///
    /// # Returns
    ///
    /// A new `OsslAesKey` instance with randomly generated key material.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesInvalidKeySize` if the requested size is invalid.
    /// Returns other `CryptoError` variants if random number generation fails.
    fn generate(size: usize) -> Result<Self::Key, CryptoError> {
        Self::validate_key_size(size)?;
        let mut key = vec![0u8; size];
        Rng::rand_bytes(&mut key)?;
        Ok(OsslAesKey::new(&key))
    }
}

impl OsslAesKey {
    /// Creates a new AES key from raw bytes.
    ///
    /// This is an internal constructor that stores the key material.
    ///
    /// # Arguments
    ///
    /// * `key` - Raw key bytes
    ///
    /// # Returns
    ///
    /// A new `OsslAesKey` instance.
    fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// This method provides internal access to the key material for use
    /// in cryptographic operations.
    ///
    /// # Returns
    ///
    /// A byte slice containing the raw AES key material.
    ///
    /// # Security
    ///
    /// This method is crate-private to prevent uncontrolled access to
    /// sensitive key material.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.key
    }

    /// Validates that the key size is valid for AES.
    ///
    /// # Arguments
    ///
    /// * `key_size` - Size of the key in bytes
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the key size is valid (16, 24, or 32 bytes)
    /// * `Err(CryptoError::AesInvalidKeySize)` - If the key size is invalid
    fn validate_key_size(key_size: usize) -> Result<(), CryptoError> {
        match key_size {
            16 | 24 | 32 => Ok(()),
            _ => Err(CryptoError::AesInvalidKeySize),
        }
    }
}
