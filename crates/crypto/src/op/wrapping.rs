// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Traits for cryptographic key wrapping and unwrapping operations.
//!
//! This module provides trait definitions for key wrapping and unwrapping,
//! which are specialized encryption operations designed for protecting
//! cryptographic key material during transport or storage.
//!
//! # Key Wrapping
//!
//! Key wrapping is a cryptographic technique that encrypts one key (the target key)
//! using another key (the wrapping key). Unlike general-purpose encryption, key
//! wrapping algorithms are specifically designed to:
//!
//! - Provide both confidentiality and integrity protection for key material
//! - Detect tampering or corruption of wrapped keys
//! - Work with key material of various sizes
//! - Meet regulatory requirements for key management
//!
//! # Common Algorithms
//!
//! Standard key wrapping algorithms include:
//! - **AES Key Wrap (RFC 3394)**: Wraps keys using AES with a 64-bit integrity check
//! - **AES-GCM**: Uses authenticated encryption for key wrapping
//! - **RSA-OAEP**: Asymmetric key wrapping using RSA encryption
//!
//! # Use Cases
//!
//! Key wrapping is commonly used for:
//! - Key transport between systems or security domains
//! - Key storage in untrusted environments
//! - Key backup and archival
//! - Key escrow systems
//! - Hardware security module (HSM) key import/export

use super::*;

/// Trait for cryptographic key wrapping operations.
///
/// This trait defines the interface for wrapping (encrypting) cryptographic keys
/// using a key encryption key (KEK). Key wrapping provides both confidentiality
/// and integrity protection for key material, ensuring that keys can be safely
/// transported or stored in untrusted environments.
///
/// # Type Parameters
///
/// * `Key` - The wrapping key type, must implement [`WrappingKey`]
/// * `TargetKey` - The key type to be wrapped, must implement [`Key`]
///
/// # Security Considerations
///
/// Key wrapping operations should:
/// - Use authenticated encryption or include integrity checks
/// - Prevent wrapping of weak or compromised keys
/// - Support key usage policy enforcement
/// - Log wrapping operations for audit purposes
/// - Validate that wrapping keys have appropriate permissions
pub trait WrapOp {
    /// The wrapping key type used to encrypt the target key.
    type Key: WrappingKey;

    /// Wraps (encrypts) a target key using a wrapping key.
    ///
    /// This method encrypts the target key with the wrapping key, producing
    /// wrapped key material that includes both the encrypted key and integrity
    /// information. The method follows a two-phase pattern: first call with
    /// `None` to get the required buffer size, second call with a buffer to
    /// perform the actual wrapping.
    ///
    /// # Arguments
    ///
    /// * `key` - The wrapping key (KEK) used to encrypt the target key
    /// * `target_key` - The key to be wrapped (encrypted)
    /// * `wrapped_key` - Optional output buffer for the wrapped key material.
    ///   If `None`, only returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer, or the required
    /// buffer size if `wrapped_key` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The wrapping key is invalid or lacks appropriate permissions
    /// - The target key cannot be exported/wrapped
    /// - The wrapping operation fails due to algorithm-specific issues
    /// - Platform-specific cryptographic operations fail
    ///
    /// # Security
    ///
    /// - The wrapped key output can be stored or transmitted safely
    /// - The integrity of wrapped keys is protected
    /// - Wrapped keys can only be unwrapped with the correct unwrapping key
    /// - Clear the wrapped key buffer when no longer needed
    fn wrap_key<TargetKey: ExportableKey>(
        &mut self,
        key: &Self::Key,
        target_key: &TargetKey,
        wrapped_key: Option<&mut [u8]>,
    ) -> Result<usize, CryptoError>;
}

/// Trait for cryptographic key unwrapping operations.
///
/// This trait defines the interface for unwrapping (decrypting) cryptographic keys
/// that have been previously wrapped. Key unwrapping verifies the integrity of the
/// wrapped key material and recovers the original plaintext key.
///
/// # Type Parameters
///
/// * `Key` - The unwrapping key type, must implement [`WrappingKey`]
/// * `TargetKey` - The key type to be unwrapped, must implement [`Key`]
///
/// # Security Considerations
///
/// Key unwrapping operations should:
/// - Verify integrity before returning unwrapped key material
/// - Fail securely if integrity checks fail (prevent padding oracle attacks)
/// - Enforce key usage policies on unwrapped keys
/// - Log unwrapping operations for audit purposes
/// - Validate that unwrapping keys have appropriate permissions
/// - Clear unwrapped key material from memory when no longer needed
pub trait UnwrapOp {
    /// The unwrapping key type used to decrypt the wrapped key.
    type Key: UnwrappingKey;

    /// Unwraps (decrypts) a wrapped key using an unwrapping key.
    ///
    /// This method decrypts wrapped key material using the unwrapping key,
    /// verifies its integrity, and recovers the original plaintext key. The
    /// method follows a two-phase pattern: first call with `None` to get the
    /// required buffer size, second call with a buffer to perform the actual
    /// unwrapping.
    ///
    /// # Arguments
    ///
    /// * `key` - The unwrapping key (KEK) used to decrypt the wrapped key
    /// * `target_key` - Template or metadata for the key being unwrapped
    /// * `wrapped_key` - The wrapped (encrypted) key material to unwrap
    /// * `unwrapped_key` - Optional output buffer for the unwrapped key material.
    ///   If `None`, only returns the required buffer size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer, or the required
    /// buffer size if `unwrapped_key` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small
    /// - The unwrapping key is invalid or lacks appropriate permissions
    /// - The wrapped key material is corrupted or has been tampered with
    /// - Integrity verification fails
    /// - The unwrapping operation fails due to algorithm-specific issues
    /// - Platform-specific cryptographic operations fail
    ///
    /// # Security
    ///
    /// - Integrity is verified before returning unwrapped key material
    /// - Failures do not leak information about the wrapped key
    /// - Unwrapped key material must be cleared from memory after use
    /// - Timing attacks are mitigated during integrity verification
    fn unwrap_key<TargetKey: ImportableKey>(
        &mut self,
        key: &Self::Key,
        wrapped_key: &[u8],
    ) -> Result<TargetKey, CryptoError>;
}
