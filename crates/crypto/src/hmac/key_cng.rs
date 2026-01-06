// Copyright (C) Microsoft Corporation. All rights reserved.

//! HMAC key implementation.
//!
//! This module provides an HMAC key implementation that can be used for
//! Hash-based Message Authentication Code operations. The key supports standard
//! operations including generation, import, and export.

use super::*;

/// An HMAC key for Hash-based Message Authentication Code operations.
///
/// This structure holds raw key material in memory and implements all necessary
/// traits for key management operations. It is specifically designed for use
/// with HMAC algorithms (HMAC-SHA256, HMAC-SHA384, HMAC-SHA512).
///
/// # Implemented Traits
///
/// This type implements the following traits:
/// - [`Key`] - Marks this as a cryptographic key type
/// - [`SymmetricKey`] - Provides symmetric key operations like length queries
/// - [`SecretKey`] - Marks this as a secret (symmetric) key
/// - [`KeyImportOp`] - Enables importing keys from raw bytes
/// - [`KeyExportOp`] - Enables exporting keys to raw bytes
/// - [`KeyGenerationOp`] - Enables generating new keys with secure randomness
///
/// # Security Considerations
///
/// - Key material is stored in a `Vec<u8>` and should be zeroized when dropped
/// - Keys should be generated using cryptographically secure random sources
/// - Exported keys should be handled carefully and encrypted before storage
/// - Access to key material should be restricted and audited
#[derive(Clone)]
pub struct CngHmacKey {
    key_data: Vec<u8>,
}

/// Marks this type as a cryptographic key.
impl Key for CngHmacKey {
    /// Returns the size of the AES key in bytes.
    ///
    /// The key size is 16 (AES-128), 24 (AES-192), or 32 (AES-256).
    fn size(&self) -> usize {
        self.key_data.len()
    }

    /// Returns the length of the AES key in bits.
    ///
    /// The key size is 128 (AES-128), 192 (AES-192), or 256 (AES-256) bits.
    fn bits(&self) -> usize {
        self.key_data.len() * 8
    }
}

impl SymmetricKey for CngHmacKey {}

/// Marks this type as a secret (symmetric) key.
impl SecretKey for CngHmacKey {}

/// Marks this type as a signing key for HMAC operations.
///
/// HMAC keys are used to create message authentication codes (MACs) that
/// authenticate message integrity and origin.
impl SigningKey for CngHmacKey {}

/// Marks this type as a verification key for HMAC operations.
///
/// The same HMAC key is used for both signing (MAC creation) and verification,
/// as HMAC is a symmetric authentication scheme.
impl VerificationKey for CngHmacKey {}

/// Marks this key as importable.
impl ImportableKey for CngHmacKey {
    /// Imports a key from raw byte representation.
    ///
    /// Creates a new HMAC key from the provided byte data. No validation is
    /// performed, allowing keys of any size to be imported. For security, HMAC
    /// keys should typically be at least as long as the hash output size.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key material to import
    ///
    /// # Returns
    ///
    /// A new `CngHmacKey` instance containing the imported key material.
    ///
    /// # Errors
    ///
    /// This implementation does not fail but returns Result for trait compatibility.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key_data: bytes.to_vec(),
        })
    }
}

/// Marks this key as exportable.
impl ExportableKey for CngHmacKey {
    /// Exports the key to byte representation.
    ///
    /// This method can either query the required buffer size (when `bytes` is `None`)
    /// or copy the key material to a provided buffer (when `bytes` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer for the key material
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if no buffer was provided.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::AesBufferTooSmall` if the provided buffer is too small
    /// to hold the key material.
    ///
    /// # Security Warning
    ///
    /// Exported key material must be handled securely:
    /// - Clear the buffer after use to prevent key leakage
    /// - Encrypt keys before storage or transmission
    /// - Use secure channels for key transport
    /// - Implement appropriate access controls
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let key_len = self.key_data.len();
        if let Some(bytes) = bytes {
            if bytes.len() < key_len {
                return Err(CryptoError::AesBufferTooSmall);
            }
            bytes[..key_len].copy_from_slice(&self.key_data);
        }
        Ok(key_len)
    }
}

impl KeyGenerationOp for CngHmacKey {
    type Key = Self;

    /// Generates a new HMAC key with cryptographically secure random data.
    ///
    /// Creates a new key of the specified size using a cryptographically secure
    /// random number generator. The generated key material has sufficient entropy
    /// for HMAC operations. For optimal security, the key size should be at least
    /// as long as the hash function's output size.
    ///
    /// # Arguments
    ///
    /// * `size` - The desired key size in bytes (typically 32, 48, or 64 bytes)
    ///
    /// # Returns
    ///
    /// A new `HmacKey` instance with randomly generated key material.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Random number generation fails
    /// - System resources are unavailable
    /// - Platform-specific RNG operations fail
    fn generate(size: usize) -> Result<Self::Key, CryptoError> {
        let mut key_data = vec![0u8; size];
        Rng::rand_bytes(&mut key_data)?;
        Ok(Self { key_data })
    }
}

impl CngHmacKey {
    /// Returns a reference to the raw key bytes.
    ///
    /// # Returns
    ///
    /// A byte slice containing the key material.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.key_data
    }
}

/// Converts GenericSecretKey to HmacKey for HMAC operations.
impl TryFrom<&GenericSecretKey> for CngHmacKey {
    type Error = CryptoError;

    fn try_from(key: &GenericSecretKey) -> Result<Self, Self::Error> {
        let key_vec = key.to_vec()?;
        HmacKey::from_bytes(key_vec.as_ref())
    }
}
