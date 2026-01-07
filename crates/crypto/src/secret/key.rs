// Copyright (C) Microsoft Corporation. All rights reserved.

//! Generic secret key implementation.
//!
//! This module provides a generic implementation of a secret (symmetric) key that
//! can be used for various cryptographic operations. The key supports standard
//! operations including generation, import, and export.

use super::*;

/// A generic secret key for symmetric cryptographic operations.
///
/// This structure holds raw key material in memory and implements all necessary
/// traits for key management operations. It can be used for any symmetric
/// algorithm that requires raw key bytes.
///
/// # Implemented Traits
///
/// This type implements the following traits:
/// - [`Key`] - Marks this as a cryptographic key type
/// - [`SymmetricKey`] - Provides symmetric key operations like length queries
/// - [`SecretKey`] - Marks this as a secret (symmetric) key
/// - [`KeyGenerationOp`] - Enables generating new keys with secure randomness
///
/// # Security Considerations
///
/// - Key material is stored in a `Vec<u8>` and should be zeroized when dropped
/// - Keys should be generated using cryptographically secure random sources
/// - Exported keys should be handled carefully and encrypted before storage
/// - Access to key material should be restricted and audited
pub struct GenericSecretKey {
    key_data: Vec<u8>,
}

/// Marks this type as a cryptographic key.
impl Key for GenericSecretKey {
    /// Returns the length of the key in bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes in the key material.
    fn size(&self) -> usize {
        self.key_data.len()
    }

    /// Returns the length of the key in bits.
    ///
    /// # Returns
    ///
    /// The number of bits in the key material (size in bytes × 8).
    fn bits(&self) -> usize {
        self.key_data.len() * 8
    }
}

impl SymmetricKey for GenericSecretKey {}

/// Marks this type as a secret (symmetric) key.
impl SecretKey for GenericSecretKey {}

// Marks this key as suitable for derivation operations.
impl DerivationKey for GenericSecretKey {}

/// Marks this key as importable.
impl ImportableKey for GenericSecretKey {
    /// Imports a key from raw byte representation.
    ///
    /// Creates a new generic secret key from the provided byte data. No
    /// validation is performed, allowing keys of any size to be imported.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw key material to import
    ///
    /// # Returns
    ///
    /// A new `GenericSecretKey` instance containing the imported key material.
    ///
    /// # Errors
    ///
    /// This implementation does not return errors, but the signature matches
    /// the trait requirement for consistency with other key types.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key_data: bytes.to_vec(),
        })
    }
}

/// Marks this key as exportable.
impl ExportableKey for GenericSecretKey {
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

impl KeyGenerationOp for GenericSecretKey {
    type Key = Self;

    /// Generates a new secret key with cryptographically secure random data.
    ///
    /// Creates a new key of the specified size using a cryptographically secure
    /// random number generator. The generated key material has sufficient entropy
    /// for cryptographic operations.
    ///
    /// # Arguments
    ///
    /// * `size` - The desired key size in bytes
    ///
    /// # Returns
    ///
    /// A new `GenericSecretKey` instance with randomly generated key material.
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
