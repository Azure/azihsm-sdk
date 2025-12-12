// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Secret key management for HKDF operations.
//!
//! This module defines the `SecretKey` type, which encapsulates key derivation key (KDK) material
//! used in HMAC-based Key Derivation Function (HKDF) workflows. It provides secure handling and
//! redacted debug output for sensitive key material. The functionality here supports RFC 5869
//! compliant key derivation, enabling extraction and expansion of cryptographic keys from shared
//! secrets or existing key material.

mod secretkey_ops;

use crate::CryptoError;

/// Represents a secret key used for HKDF operations.
///
/// # Fields
/// - `kdk`: The key derivation key material as a byte vector.
pub struct SecretKey {
    /// The key derivation key (KDK) used for cryptographic operations.
    /// This is a vector of bytes representing the secret material for key derivation.
    pub kdk: Vec<u8>,
}

/// Trait providing HKDF key derivation operations.
///
/// This trait defines the interface for HKDF key struct from
/// the perspective of key derivation operations.
pub trait SecretKeyOps {
    /// Creates a SecretKey from a byte slice.
    ///
    /// # Arguments
    /// * `key` - The input key material as a byte slice.
    ///
    /// # Returns
    /// * `Ok(Self)` - A SecretKey instance on success.
    /// * `Err(CryptoError)` - If the key is invalid or empty.
    ///
    /// # Errors
    /// * `CryptoError::HkdfSecretCreationFailed` - If the key is empty or invalid.
    fn from_slice(key: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;
}
