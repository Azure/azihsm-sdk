// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC key implementation.
//!
//! This module provides an HMAC key implementation that can be used for
//! Hash-based Message Authentication Code operations. The key supports standard
//! operations including generation, import, and export.

use openssl::pkey::*;

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
pub struct OsslHmacKey {
    key: PKey<Private>,
}

impl OsslHmacKey {
    /// Returns a reference to the internal OpenSSL PKey.
    ///
    /// This method provides internal access to the underlying OpenSSL key structure
    /// for use in HMAC operations.
    ///
    /// # Returns
    ///
    /// A reference to the OpenSSL `PKey<Private>` containing the HMAC key material.
    pub fn pkey(&self) -> &PKey<Private> {
        &self.key
    }
}

/// Marks this type as a cryptographic key.
impl Key for OsslHmacKey {
    /// Returns the length of the key in bytes.
    ///
    /// HMAC keys can be of any length, though it's recommended to use keys
    /// at least as long as the hash output size for optimal security.
    fn size(&self) -> usize {
        self.key.size()
    }

    /// Returns the length of the key in bits.
    ///
    /// This is calculated as the byte length multiplied by 8.
    fn bits(&self) -> usize {
        self.key.size() * 8
    }
}

/// Marks this type as a symmetric key.
///
/// HMAC keys are symmetric, meaning the same key is used for both
/// message authentication code generation and verification.
impl SymmetricKey for OsslHmacKey {}

/// Marks this type as a secret (symmetric) key.
impl SecretKey for OsslHmacKey {}

/// Marks this type as a signing key for HMAC operations.
///
/// HMAC keys are used to create message authentication codes (MACs) that
/// authenticate message integrity and origin.
impl SigningKey for OsslHmacKey {}

/// Marks this type as a verification key for HMAC operations.
///
/// The same HMAC key is used for both signing (MAC creation) and verification,
/// as HMAC is a symmetric authentication scheme.
impl VerificationKey for OsslHmacKey {}

/// Marks this key as importable.
impl ImportableKey for OsslHmacKey {
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
    /// A new `HmacKey` instance containing the imported key material.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::HmacKeyImportError` if key creation fails.
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            key: PKey::hmac(bytes).map_err(|_| CryptoError::HmacKeyImportError)?,
        })
    }
}

impl ExportableKey for OsslHmacKey {
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
        let key_len = self.key.size();
        if let Some(bytes) = bytes {
            if bytes.len() < key_len {
                return Err(CryptoError::HmacBufferTooSmall);
            }

            let key_bytes = self
                .key
                .raw_private_key()
                .map_err(|_| CryptoError::HmacKeyExportError)?;

            bytes[..key_bytes.len()].copy_from_slice(&key_bytes);
        }
        Ok(key_len)
    }
}

impl KeyGenerationOp for OsslHmacKey {
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
        Self::from_bytes(&key_data)
    }
}

/// Converts GenericSecretKey to HmacKey for HMAC operations.
impl TryFrom<&GenericSecretKey> for OsslHmacKey {
    type Error = CryptoError;

    fn try_from(key: &GenericSecretKey) -> Result<Self, Self::Error> {
        let key_vec = key.to_vec()?;
        HmacKey::from_bytes(key_vec.as_ref())
    }
}
