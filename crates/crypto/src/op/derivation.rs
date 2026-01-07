// Copyright (C) Microsoft Corporation. All rights reserved.

//! Key derivation operation trait.
//!
//! This module defines the [`DeriveOp`] trait, which provides a generic interface
//! for key derivation operations. Key derivation is the process of generating one
//! or more cryptographic keys from a source key material, typically using a
//! cryptographic algorithm such as HKDF or KBKDF.

use super::*;

/// Trait for key derivation operations.
///
/// This trait defines the interface for cryptographic key derivation functions (KDFs).
/// Key derivation is a cryptographic process that generates one or more secret keys
/// from a source key material, typically combined with additional context information
/// such as a salt, label, or application-specific parameters.
///
/// # Type Parameters
///
/// The trait uses associated types to ensure type safety:
/// - `Key`: The source key material used for derivation
/// - `DerivedKey`: The resulting key after derivation
///
/// # Security Considerations
///
/// Key derivation is a critical security operation. Implementations should:
/// - Use cryptographically secure derivation algorithms (e.g., HKDF, KBKDF)
/// - Protect key material in memory
/// - Follow relevant standards (NIST SP 800-108, RFC 5869)
/// - Use appropriate context information to ensure domain separation
pub trait DeriveOp {
    /// The type of the source key material used for derivation.
    ///
    /// This key serves as the input to the key derivation function and must
    /// implement the [`DeriveKey`] trait, which ensures it has the necessary
    /// properties for use in key derivation operations.
    type Key: DerivationKey;

    /// The type of the derived key produced by the derivation operation.
    ///
    /// This represents the output key after the derivation process completes
    /// successfully. It must implement the [`SecretKey`] trait to ensure proper
    /// handling of cryptographic key material.
    type DerivedKey: SecretKey;

    /// Performs the key derivation operation.
    ///
    /// This method takes source key material and derives a new cryptographic key
    /// of the specified length according to the specific derivation algorithm and
    /// parameters configured in the implementing type.
    ///
    /// # Arguments
    ///
    /// * `key` - The source key material to derive from
    /// * `derived_len` - The desired length of the derived key in bytes
    ///
    /// # Returns
    ///
    /// Returns the successfully derived key of the specified length.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The source key is invalid or has incorrect properties
    /// - The requested derived key length is invalid or unsupported
    /// - The derivation algorithm fails
    /// - Insufficient entropy is available
    /// - Platform-specific cryptographic operations fail
    /// - Hardware security module operations fail (if applicable)
    fn derive(&self, key: &Self::Key, derived_len: usize) -> Result<Self::DerivedKey, CryptoError>;
}
