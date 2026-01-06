// Copyright (C) Microsoft Corporation. All rights reserved.

//! Traits for cryptographic key type system and operations.
//!
//! This module provides trait definitions for key type markers and basic key operations
//! including import and export. These traits support various key types (symmetric,
//! asymmetric) and provide a consistent interface across different algorithms.
//!
//! # Design Philosophy
//!
//! The module uses a marker trait hierarchy to provide compile-time type safety for
//! cryptographic operations. This prevents common mistakes like using the wrong key
//! type with an operation.
//!
//! # Trait Categories
//!
//! The module provides several categories of traits:
//!
//! - **Base Traits**: [`Key`] as the root trait for all key types
//! - **Key Type Markers**: [`SymmetricKey`], [`PrivateKey`], [`PublicKey`], [`SecretKey`] for type classification
//! - **Operation Markers**: [`SigningKey`], [`VerificationKey`], [`EncryptionKey`], [`DecryptionKey`]
//! - **Key Wrapping**: [`WrappingKey`], [`UnwrappingKey`] for key transport and storage
//! - **Key Transfer**: [`ExportableKey`], [`ImportableKey`] for serialization capabilities
//! - **Derivation**: [`DerivationKey`] for key derivation operations
//! - **Import/Export Operations**: [`KeyImportOp`] and [`KeyExportOp`] for serialization
//!
//! # Key Types
//!
//! Keys are categorized by their cryptographic role:
//! - **Symmetric Keys**: Secret keys used for encryption/HMAC (e.g., AES, HMAC keys)
//! - **Private Keys**: Asymmetric private keys for signing/decryption (e.g., RSA, ECC private keys)
//! - **Public Keys**: Asymmetric public keys for verification/encryption (e.g., RSA, ECC public keys)

use super::*;

/// Base trait for all cryptographic keys.
///
/// This trait serves as the foundational marker for all key types in the library,
/// establishing that a type can be imported from and exported to byte representations.
/// All key types (symmetric, private, public) must implement this trait.
///
/// # Requirements
///
/// Keys implementing this trait automatically support:
/// - Import operations via [`KeyImportOp`] bound
/// - Export operations via [`KeyExportOp`] bound
///
/// # Key Type Hierarchy
///
/// The trait hierarchy includes these specialized key types:
/// - [`SymmetricKey`]: Symmetric/secret keys for algorithms like AES, HMAC
/// - [`PrivateKey`]: Asymmetric private keys for signing and decryption
/// - [`PublicKey`]: Asymmetric public keys for verification and encryption
/// - [`SecretKey`]: Marker for secret key material
/// - [`DerivationKey`]: Keys that can be used in key derivation operations
///
/// # Operation Markers
///
/// Keys may also implement operation-specific markers:
/// - [`SigningKey`]: Can create digital signatures
/// - [`VerificationKey`]: Can verify digital signatures
/// - [`EncryptionKey`]: Can encrypt data
/// - [`DecryptionKey`]: Can decrypt data
/// - [`WrappingKey`]: Can wrap other keys
/// - [`UnwrappingKey`]: Can unwrap other keys
/// - [`ExportableKey`]: Can be exported
/// - [`ImportableKey`]: Can be imported
pub trait Key {
    /// Returns the length of the key in bytes.
    ///
    /// # Returns
    ///
    /// The key size in bytes. Common values:
    /// - AES-128: 16 bytes
    /// - AES-192: 24 bytes
    /// - AES-256: 32 bytes
    fn size(&self) -> usize;

    /// Returns the length of the key in bits.
    ///
    /// # Returns
    ///
    /// The key size in bits. Common values:
    /// - AES-128: 128 bits
    /// - AES-192: 192 bits
    /// - AES-256: 256 bits
    /// - RSA-2048: 2048 bits
    /// - RSA-3072: 3072 bits
    /// - RSA-4096: 4096 bits
    fn bits(&self) -> usize;
}

/// Marker trait for symmetric (secret) keys.
///
/// This trait identifies key types used in symmetric cryptography, where the same
/// key is used for both encryption and decryption (or signing and verification in
/// the case of HMAC).
///
/// # Type Safety
///
/// This marker trait enables compile-time verification that the correct key type
/// is being used with symmetric operations, preventing accidental use of asymmetric
/// keys where symmetric keys are required.
///
/// # Implementations
///
/// Common implementations include:
/// - AES keys (128, 192, or 256 bits)
/// - HMAC keys (variable length)
/// - ChaCha20 keys (256 bits)
///
/// # Security
///
/// Symmetric keys must be:
/// - Generated with sufficient entropy
/// - Kept secret and never exposed
/// - Used with appropriate modes of operation
/// - Rotated according to security policy
pub trait SymmetricKey: Key {}

/// Marker trait for asymmetric private keys.
///
/// This trait identifies key types used as private keys in asymmetric (public-key)
/// cryptography. Private keys must be kept secret and are used for:
/// - Digital signature creation
/// - Decryption of messages encrypted with the corresponding public key
/// - Key agreement protocols
///
/// # Security
///
/// Private keys must be:
/// - Stored securely (encrypted at rest when possible)
/// - Never transmitted in plaintext
/// - Properly zeroized from memory when no longer needed
/// - Protected with appropriate access controls
pub trait PrivateKey: Key {
    /// The corresponding public key type for this private key.
    type PublicKey: PublicKey;

    /// Derives the public key from this private key.
    ///
    /// This method computes the corresponding public key from the private key
    /// material. For elliptic curve keys, this involves multiplying the generator
    /// point by the private key scalar. For RSA, this extracts the public exponent
    /// and modulus.
    ///
    /// # Returns
    ///
    /// The corresponding public key that can be safely shared.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The private key is invalid or corrupted
    /// - Public key derivation fails
    /// - Platform-specific operations fail
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError>;
}

/// Marker trait for asymmetric public keys.
///
/// This trait identifies key types used as public keys in asymmetric (public-key)
/// cryptography. Public keys can be freely distributed and are used for:
/// - Digital signature verification
/// - Encryption of messages (decryptable only by the corresponding private key)
/// - Key agreement protocols
pub trait PublicKey: Key {}

/// Marker trait for keys that can be used in key derivation operations.
///
/// This trait identifies key types that are suitable for use as source material
/// in key derivation functions (KDFs) or key agreement protocols. Keys implementing
/// this trait can be used with the [`DeriveOp`] trait to produce derived key material.
///
/// # Security
///
/// Keys used for derivation should:
/// - Have sufficient entropy for the derivation algorithm
/// - Be protected with the same security measures as encryption keys
/// - Not be reused across different contexts without proper domain separation
pub trait DerivationKey: Key {}

/// Marker trait for secret (symmetric) key material.
///
/// This trait identifies cryptographic keys that must be kept secret and are
/// used in symmetric cryptographic operations. Unlike [`SymmetricKey`], this is
/// a pure marker trait without additional methods.
///
/// # Relationship to SymmetricKey
///
/// While related to [`SymmetricKey`], this trait serves as a simpler marker for
/// types that represent secret key material, potentially including intermediate
/// key derivation outputs or key agreement results that will be used for
/// symmetric operations.
///
/// # Security
///
/// Secret keys must:
/// - Never be exposed in logs or debug output
/// - Be zeroized from memory when no longer needed
/// - Be encrypted when stored persistently
/// - Be transmitted only over secure, authenticated channels
pub trait SecretKey: Key {}

/// Marker trait for keys used in digital signature creation.
///
/// This trait identifies key types that can be used to create digital signatures.
/// Typically, signing keys are private keys in asymmetric cryptography or secret
/// keys in symmetric authentication schemes like HMAC.
///
/// # Key Types
///
/// Signing keys include:
/// - ECC private keys (ECDSA, EdDSA)
/// - RSA private keys
/// - HMAC secret keys (for message authentication codes)
///
/// # Security
///
/// Signing keys must be:
/// - Protected with the same security measures as private keys
/// - Never exposed to untrusted parties
/// - Used only for signature creation, not verification
/// - Properly zeroized from memory when no longer needed
pub trait SigningKey: Key {}

/// Marker trait for keys used in digital signature or MAC verification.
///
/// This trait identifies key types that can be used to verify digital signatures
/// or message authentication codes. For asymmetric cryptography, these are public
/// keys. For symmetric schemes like HMAC, the same secret key is used for both
/// signing and verification.
///
/// # Key Types
///
/// Verification keys include:
/// - ECC public keys (ECDSA, EdDSA)
/// - RSA public keys
/// - HMAC secret keys (for message authentication code verification)
///
/// # Security
///
/// Verification keys:
/// - Can be freely distributed if they are public keys
/// - Must be authenticated to prevent key substitution attacks
/// - Should be bound to an identity (e.g., via certificates)
pub trait VerificationKey: Key {}

/// Marker trait for keys used in encryption operations.
///
/// This trait identifies key types that can be used to encrypt data. For
/// symmetric cryptography, the encryption key is the same as the decryption
/// key. For asymmetric cryptography, encryption is performed with the public
/// key, and decryption requires the corresponding private key.
///
/// # Key Types
///
/// Encryption keys include:
/// - Symmetric keys (AES, ChaCha20) for symmetric encryption
/// - RSA public keys for asymmetric encryption
/// - ECC public keys for ECIES encryption
///
/// # Security
///
/// Symmetric encryption keys must be:
/// - Kept secret and never exposed to untrusted parties
/// - Used with appropriate modes of operation (e.g., GCM, CBC with HMAC)
/// - Never reused for different contexts without proper domain separation
///
/// Public encryption keys:
/// - Can be freely distributed
/// - Should be authenticated to prevent key substitution attacks
/// - Should be bound to an identity through certificates or similar mechanisms
pub trait EncryptionKey: Key {}

/// Marker trait for keys used in decryption operations.
///
/// This trait identifies key types that can be used to decrypt data. For
/// symmetric cryptography, the decryption key is the same as the encryption
/// key. For asymmetric cryptography, decryption requires the private key
/// corresponding to the public key used for encryption.
///
/// # Key Types
///
/// Decryption keys include:
/// - Symmetric keys (AES, ChaCha20) for symmetric decryption
/// - RSA private keys for asymmetric decryption
/// - ECC private keys for ECIES decryption
///
/// # Security
///
/// Decryption keys must be:
/// - Protected with the highest security measures (similar to private keys)
/// - Stored encrypted when at rest
/// - Never exposed in logs or transmitted unencrypted
/// - Properly zeroized from memory when no longer needed
/// - Protected with appropriate access controls
pub trait DecryptionKey: Key {}

/// Marker trait for keys used in key wrapping operations.
///
/// This trait identifies key types that can be used to wrap (encrypt) other
/// cryptographic keys. Key wrapping is a specialized form of encryption designed
/// specifically for encrypting key material, providing both confidentiality and
/// integrity protection.
///
/// # Purpose
///
/// Key wrapping is used to:
/// - Securely transport keys between systems
/// - Store keys in untrusted storage
/// - Share keys between different security domains
/// - Establish key hierarchies (e.g., master keys wrapping working keys)
///
/// # Key Types
///
/// Wrapping keys include:
/// - Symmetric keys used with AES Key Wrap (RFC 3394) or AES-GCM
/// - RSA public keys for asymmetric key wrapping
/// - Key Encryption Keys (KEKs) in key management hierarchies
///
/// # Security
///
/// Wrapping keys must:
/// - Be at least as strong as the keys they protect
/// - Be stored with the highest security measures
/// - Have restricted usage permissions (wrap operations only)
/// - Be rotated according to security policy
/// - Never be used for general-purpose encryption
pub trait WrappingKey: Key {}

/// Marker trait for keys used in key unwrapping operations.
///
/// This trait identifies key types that can be used to unwrap (decrypt) other
/// cryptographic keys that have been wrapped for secure transport or storage.
/// Key unwrapping verifies integrity and recovers the plaintext key material.
///
/// # Purpose
///
/// Key unwrapping is used to:
/// - Recover keys after secure transport
/// - Load keys from encrypted storage
/// - Import keys across security boundaries
/// - Recover working keys from key hierarchies
///
/// # Key Types
///
/// Unwrapping keys include:
/// - Symmetric keys used with AES Key Wrap (RFC 3394) or AES-GCM
/// - RSA private keys for asymmetric key unwrapping
/// - Key Encryption Keys (KEKs) in key management hierarchies
///
/// # Security
///
/// Unwrapping keys must:
/// - Be protected with the highest security measures (like private keys)
/// - Be stored encrypted when at rest
/// - Have restricted usage permissions (unwrap operations only)
/// - Verify integrity of wrapped keys before unwrapping
/// - Never be exposed in logs or error messages
/// - Be properly zeroized from memory when no longer needed
pub trait UnwrappingKey: Key {}

/// Marker trait for keys that can be exported.
///
/// This trait identifies key types that support export operations, allowing
/// their key material to be serialized to bytes for storage, transmission, or
/// interoperability with external systems.
///
/// # Purpose
///
/// Key export is used to:
/// - Store keys in key stores or databases
/// - Transmit keys securely between systems
/// - Backup key material
/// - Integrate with external cryptographic systems
/// - Convert keys between different formats or representations
///
/// # Security
///
/// When exporting keys:
/// - Private/secret keys should be encrypted before export
/// - Use secure channels for transmission
/// - Apply appropriate access controls
/// - Clear exported key material from memory after use
/// - Consider key wrapping for additional protection
pub trait ExportableKey: Key {
    /// Exports a key to byte representation.
    ///
    /// Serializes the key to a byte format. This method uses a two-phase pattern:
    /// 1. Call with `None` to query the required buffer size
    /// 2. Allocate a buffer of the appropriate size
    /// 3. Call again with the buffer to perform the actual export
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, only calculates required size.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to the buffer, or the required
    /// buffer size if `bytes` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The output buffer is too small (returns `CryptoError::BufferTooSmall` or similar)
    /// - The key is in an invalid state
    /// - Platform-specific serialization fails
    /// - The key type does not support export
    ///
    /// # Security
    ///
    /// For private/secret keys:
    /// - Clear the output buffer when no longer needed
    /// - Consider encrypting the output before storage
    /// - Use secure transmission channels
    /// - Implement appropriate access controls
    /// - Never log or display the exported key material
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError>;

    /// Exports a key to a newly allocated vector.
    ///
    /// This is a convenience method that allocates the output buffer automatically.
    /// It first queries the required size using `to_bytes(None)`, allocates a
    /// vector of the appropriate size, and then exports the key into it.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the serialized key data.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is in an invalid state
    /// - Platform-specific serialization fails
    /// - The key type does not support export
    /// - Memory allocation fails
    ///
    /// # Security
    ///
    /// For private/secret keys:
    /// - Clear the returned vector when no longer needed
    /// - Consider encrypting the data before storage
    /// - Use secure transmission channels
    /// - Implement appropriate access controls
    fn to_vec(&self) -> Result<Vec<u8>, CryptoError> {
        let size = self.to_bytes(None)?;
        let mut buffer = vec![0u8; size];
        self.to_bytes(Some(&mut buffer))?;
        Ok(buffer)
    }
}

/// Marker trait for keys that can be imported.
///
/// This trait identifies key types that support import operations, allowing
/// keys to be deserialized from byte representations. This enables loading
/// keys from storage, receiving keys from other systems, or converting keys
/// from external formats.
///
/// # Purpose
///
/// Key import is used to:
/// - Load keys from key stores or databases
/// - Receive keys transmitted from other systems
/// - Restore keys from backup
/// - Integrate keys from external cryptographic systems
/// - Convert keys from different formats or representations
///
/// # Security
///
/// When importing keys:
/// - Validate key material before import
/// - Use secure channels for transmission
/// - Verify key authenticity and integrity
/// - Apply appropriate access controls
/// - Clear temporary import buffers from memory
/// - Consider key unwrapping if keys are wrapped
pub trait ImportableKey: Key {
    /// Imports a key from raw byte representation.
    ///
    /// Deserializes a key from its byte representation. The format depends on
    /// the key type:
    /// - Symmetric keys: Raw key bytes
    /// - Asymmetric keys: May require DER or other structured format
    ///
    /// # Arguments
    ///
    /// * `bytes` - The serialized key data
    ///
    /// # Returns
    ///
    /// Returns a key of type `Self::Key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input data is malformed or corrupted
    /// - The key format is invalid for this algorithm
    /// - The key size is unsupported
    /// - Cryptographic validation fails (e.g., invalid curve point)
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;
}

/// Trait for cryptographic key generation operations.
///
/// This trait provides an interface for generating new cryptographic keys with
/// cryptographically secure randomness. It supports various key types and sizes
/// depending on the algorithm requirements.
///
/// # Type Parameters
///
/// * `Key` - The key type to generate, implementing one of the key marker traits
///
/// # Security Considerations
///
/// Key generation must use a cryptographically secure random number generator (CSPRNG).
/// The generated keys should have sufficient entropy to resist brute-force attacks.
pub trait KeyGenerationOp {
    /// The type of key this operation generates.
    type Key: Key;

    /// Generates a new cryptographic key.
    ///
    /// Creates a new key with cryptographically secure random data appropriate
    /// for the algorithm. For algorithms with variable key sizes (e.g., HMAC),
    /// the size parameter determines the key length. For fixed-size algorithms
    /// (e.g., AES-256), the size parameter may be ignored or used for validation.
    ///
    /// # Arguments
    ///
    /// * `size` - The desired key size in bytes. Interpretation depends on the algorithm:
    ///   - For AES: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    ///   - For HMAC: Typically hash output size or larger
    ///   - For ECC: Ignored (curve determines key size)
    ///   - For RSA: Key modulus size in bits (converted from bytes)
    ///
    /// # Returns
    ///
    /// Returns a new key of type `Self::Key`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The requested key size is invalid for the algorithm
    /// - Random number generation fails
    /// - System resources are unavailable
    /// - Platform-specific key generation fails
    fn generate(size: usize) -> Result<Self::Key, CryptoError>;
}
