// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based RSA key operations.
//!
//! This module provides RSA private and public key implementations using OpenSSL
//! as the underlying cryptographic backend. It supports various RSA key sizes
//! for key generation, import, and export operations.
//!
//! # Supported Key Sizes
//!
//! - **2048-bit**: Minimum recommended size for new applications
//! - **3072-bit**: Enhanced security
//! - **4096-bit**: High security applications
//!
//! # Key Formats
//!
//! Keys are imported and exported in DER encoding format:
//! - Private keys: PKCS#8 format
//! - Public keys: X.509 SubjectPublicKeyInfo format
//!
//! # Security Considerations
//!
//! - Private keys should be stored securely and never transmitted unencrypted
//! - Use minimum 2048-bit keys for new applications (3072-bit or 4096-bit recommended)
//! - Public keys can be freely distributed for signature verification and encryption
//! - Key generation uses cryptographically secure random number generation

use openssl::pkey::*;

use super::*;

/// OpenSSL RSA private key implementation.
///
/// This structure wraps an OpenSSL RSA private key and provides operations for
/// key generation, import, export, and public key derivation. Private keys contain
/// the private exponent and other RSA parameters needed for decryption and signing.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's RSA key operations are thread-safe.
///
/// # Security
///
/// Private keys should be:
/// - Protected from unauthorized access
/// - Securely zeroed when no longer needed
/// - Never transmitted or stored without encryption
/// - Generated using cryptographically secure random sources
pub struct OsslRsaPrivateKey {
    /// The underlying OpenSSL RSA private key
    key: PKey<Private>,
}

/// OpenSSL RSA public key implementation.
///
/// This structure wraps an OpenSSL RSA public key and provides operations for
/// key import and export. Public keys contain the public exponent and modulus
/// and can be freely distributed for signature verification and encryption.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's RSA key operations are thread-safe.
///
/// # Security
///
/// Public keys:
/// - Can be freely transmitted and stored
/// - Should be authenticated to prevent man-in-the-middle attacks
/// - Are derived from private keys and cannot be reversed to obtain the private key
#[derive(Debug)]
pub struct OsslRsaPublicKey {
    /// The underlying OpenSSL RSA public key
    key: PKey<Public>,
}

/// Marks this type as a cryptographic key.
impl Key for OsslRsaPrivateKey {
    /// Returns the length of the RSA private key in bytes.
    ///
    /// The size corresponds to the modulus size:
    /// - 256 bytes (2048 bits)
    /// - 384 bytes (3072 bits)
    /// - 512 bytes (4096 bits)
    fn size(&self) -> usize {
        self.key.size()
    }

    /// Returns the length of the RSA private key in bits.
    ///
    /// Common values are 2048, 3072, or 4096 bits.
    fn bits(&self) -> usize {
        self.key.bits() as usize
    }
}

/// Marks this type as a signing key for RSA signature operations.
///
/// RSA private keys can create digital signatures that authenticate messages
/// and prove the identity of the signer.
impl SigningKey for OsslRsaPrivateKey {}

/// Marks this type as a key usable in decryption operations.
///
/// RSA private keys can decrypt data that was encrypted with the corresponding
/// public key.
impl DecryptionKey for OsslRsaPrivateKey {}

/// Marks this type as a key usable in unwrapping operations.
///
/// RSA private keys can unwrap (decrypt) key material that was wrapped with
/// the corresponding public key.
impl UnwrappingKey for OsslRsaPrivateKey {}

impl PrivateKey for OsslRsaPrivateKey {
    type PublicKey = OsslRsaPublicKey;

    /// Derives the public key from this private key.
    ///
    /// This method extracts the public exponent and modulus from the private key.
    /// The operation is deterministic and always produces the same public key for
    /// a given private key.
    ///
    /// # Returns
    ///
    /// The corresponding public key on success.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccError` if the public key extraction fails.
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        let der = self
            .key
            .public_key_to_der()
            .map_err(|_| CryptoError::EccError)?;
        let key = PKey::public_key_from_der(&der).map_err(|_| CryptoError::EccError)?;
        Ok(OsslRsaPublicKey::new(key))
    }
}

/// Marks this key as importable.
impl ImportableKey for OsslRsaPrivateKey {
    /// Imports an RSA private key from DER-encoded bytes.
    ///
    /// This method parses a DER-encoded private key in PKCS#8 format.
    /// The key must be properly formatted and contain valid RSA parameters.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded private key data
    ///
    /// # Returns
    ///
    /// A new private key instance on success.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccKeyImportError` if:
    /// - The DER encoding is invalid
    /// - The RSA parameters are invalid
    /// - The key format is not supported
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pkey = PKey::private_key_from_der(bytes).map_err(|_| CryptoError::EccKeyImportError)?;

        let rsa = pkey.rsa().map_err(|_| CryptoError::EccKeyImportError)?;

        if !is_valid_key_size(rsa.size() as usize) {
            return Err(CryptoError::EccInvalidKeySize);
        }

        Ok(OsslRsaPrivateKey::new(pkey))
    }
}

impl ExportableKey for OsslRsaPrivateKey {
    /// Exports this RSA private key to DER-encoded bytes.
    ///
    /// This method encodes the private key in PKCS#8 format,
    /// including all RSA parameters (modulus, exponents, primes, etc.).
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `bytes` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccKeyExportError` - DER encoding fails
    /// - `CryptoError::EccBufferTooSmall` - Output buffer is too small
    ///
    /// # Security
    ///
    /// The exported data contains the private key and must be protected.
    /// Never transmit or store private keys without encryption.
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let der = self
            .key
            .private_key_to_pkcs8()
            .map_err(|_| CryptoError::EccKeyExportError)?;
        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::EccBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }
        Ok(der.len())
    }
}

impl KeyGenerationOp for OsslRsaPrivateKey {
    type Key = Self;

    /// Generates a new RSA private key for the specified key size.
    ///
    /// This method generates a cryptographically secure random RSA key pair
    /// with the specified modulus size in bytes. The key generation uses
    /// OpenSSL's secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `size` - Modulus size in bytes (e.g., 256 for 2048-bit, 384 for 3072-bit, 512 for 4096-bit)
    ///
    /// # Returns
    ///
    /// A new randomly generated private key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccError` - RSA structure creation fails
    /// - `CryptoError::EccKeyGenError` - Key generation fails
    ///
    /// # Security
    ///
    /// Generated keys use cryptographically secure randomness and are suitable
    /// for production use. Minimum recommended size is 256 bytes (2048 bits).
    fn generate(size: usize) -> Result<Self, CryptoError> {
        // check for valid sizes via helper function
        if !is_valid_key_size(size) {
            return Err(CryptoError::EccInvalidKeySize);
        }

        let rsa = openssl::rsa::Rsa::generate(size as u32 * 8)
            .map_err(|_| CryptoError::EccKeyGenError)?;
        let pkey = PKey::from_rsa(rsa).map_err(|_| CryptoError::EccError)?;
        Ok(OsslRsaPrivateKey::new(pkey))
    }
}

impl RsaKeyOp for OsslRsaPrivateKey {
    /// Retrieves the RSA modulus (n) from the private key.
    ///
    /// This method can either return the required buffer size (when `n` is `None`)
    /// or copy the modulus to the provided buffer (when `n` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `n` - Optional output buffer for the modulus
    ///
    /// # Returns
    ///
    /// The size of the modulus in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn n(&self, n: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let rsa = self.key.rsa().map_err(|_| CryptoError::EccError)?;
        let len = rsa.n().num_bytes() as usize;
        if let Some(n) = n {
            if n.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }
            n[..len].copy_from_slice(&rsa.n().to_vec());
        }
        Ok(len)
    }

    /// Retrieves the RSA public exponent (e) from the private key.
    ///
    /// This method can either return the required buffer size (when `e` is `None`)
    /// or copy the exponent to the provided buffer (when `e` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `e` - Optional output buffer for the exponent
    ///
    /// # Returns
    ///
    /// The size of the exponent in bytes (typically 3 bytes for value 65537).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn e(&self, e: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let rsa = self.key.rsa().map_err(|_| CryptoError::EccError)?;
        let len = rsa.e().num_bytes() as usize;
        if let Some(e) = e {
            if e.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }
            e[..len].copy_from_slice(&rsa.e().to_vec());
        }
        Ok(len)
    }
}

impl OsslRsaPrivateKey {
    /// Creates a new private key wrapper from an OpenSSL RSA key.
    ///
    /// This is an internal constructor used to wrap an existing OpenSSL key.
    ///
    /// # Arguments
    ///
    /// * `key` - An OpenSSL RSA private key
    ///
    /// # Returns
    ///
    /// A new `OsslRsaPrivateKey` instance wrapping the provided key.
    fn new(key: PKey<Private>) -> Self {
        Self { key }
    }

    /// Generates a new RSA private key for the specified key size.
    ///
    /// This is a convenience method that generates a key using the predefined
    /// key size enum rather than a numeric byte size.
    ///
    /// # Arguments
    ///
    /// * `curve` - The RSA key size to use (converted from EccCurve for compatibility)
    ///
    /// # Returns
    ///
    /// A new randomly generated private key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccError` - RSA structure creation fails
    /// - `CryptoError::EccKeyGenError` - Key generation fails
    pub fn from_curve(curve: EccCurve) -> Result<Self, CryptoError> {
        Self::generate(curve.into())
    }

    /// Returns a reference to the underlying OpenSSL private key.
    ///
    /// This is an internal method used by other cryptographic operations that
    /// need direct access to the OpenSSL key structure.
    ///
    /// # Returns
    ///
    /// A reference to the OpenSSL `PKey<Private>` wrapper.
    pub(crate) fn pkey(&self) -> &PKeyRef<Private> {
        &self.key
    }
}

/// Marks this type as a cryptographic key.
impl Key for OsslRsaPublicKey {
    /// Returns the length of the RSA public key in bytes.
    ///
    /// The size corresponds to the modulus size:
    /// - 256 bytes (2048 bits)
    /// - 384 bytes (3072 bits)
    /// - 512 bytes (4096 bits)
    fn size(&self) -> usize {
        self.key.size()
    }

    /// Returns the length of the RSA public key in bits.
    ///
    /// Common values are 2048, 3072, or 4096 bits.
    fn bits(&self) -> usize {
        self.key.bits() as usize
    }
}
/// Marks this type as a key usable in wrapping operations.
///
/// RSA public keys can wrap (encrypt) key material for secure transport.
impl WrappingKey for OsslRsaPublicKey {}

/// Marks this type as a verification key for RSA signature operations.
///
/// RSA public keys can verify digital signatures created by the corresponding
/// private key, ensuring message authenticity and integrity.
impl VerificationKey for OsslRsaPublicKey {}

/// Marks this type as an encryption key for RSA encryption operations.
///
/// RSA public keys can encrypt data that can only be decrypted by the
/// corresponding private key.
impl EncryptionKey for OsslRsaPublicKey {}

/// Marks this type as an asymmetric public key.
///
/// Public keys can be freely distributed and used for signature verification
/// and encryption operations.
impl PublicKey for OsslRsaPublicKey {}

/// Marks this key as importable.
impl ImportableKey for OsslRsaPublicKey {
    /// Imports an RSA public key from DER-encoded bytes.
    ///
    /// This method parses a DER-encoded public key in X.509 SubjectPublicKeyInfo
    /// format. The key must be properly formatted and contain valid RSA parameters.
    ///
    /// # Arguments
    ///
    /// * `bytes` - DER-encoded public key data
    ///
    /// # Returns
    ///
    /// A new public key instance on success.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccKeyImportError` if:
    /// - The DER encoding is invalid
    /// - The RSA parameters are invalid
    /// - The key format is not supported
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let rsa = openssl::rsa::Rsa::public_key_from_der(bytes)
            .map_err(|_| CryptoError::EccKeyImportError)?;
        if !is_valid_key_size(rsa.size() as usize) {
            return Err(CryptoError::EccInvalidKeySize);
        }
        let pkey = PKey::from_rsa(rsa).map_err(|_| CryptoError::EccError)?;
        Ok(OsslRsaPublicKey::new(pkey))
    }
}

impl ExportableKey for OsslRsaPublicKey {
    /// Exports this RSA public key to DER-encoded bytes.
    ///
    /// This method encodes the public key in X.509 SubjectPublicKeyInfo format,
    /// including the modulus and public exponent.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Optional output buffer. If `None`, returns the required buffer size.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the buffer, or the required buffer size
    /// if `bytes` is `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccKeyExportError` - DER encoding fails
    /// - `CryptoError::EccBufferTooSmall` - Output buffer is too small
    fn to_bytes(&self, bytes: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let der = self
            .key
            .public_key_to_der()
            .map_err(|_| CryptoError::EccKeyExportError)?;
        if let Some(bytes) = bytes {
            if bytes.len() < der.len() {
                return Err(CryptoError::EccBufferTooSmall);
            }
            bytes[..der.len()].copy_from_slice(&der);
        }
        Ok(der.len())
    }
}

impl RsaKeyOp for OsslRsaPublicKey {
    /// Retrieves the RSA modulus (n) from the public key.
    ///
    /// This method can either return the required buffer size (when `n` is `None`)
    /// or copy the modulus to the provided buffer (when `n` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `n` - Optional output buffer for the modulus
    ///
    /// # Returns
    ///
    /// The size of the modulus in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn n(&self, n: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let rsa = self.key.rsa().map_err(|_| CryptoError::EccError)?;
        let len = rsa.n().num_bytes() as usize;
        if let Some(n) = n {
            if n.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }
            n[..len].copy_from_slice(&rsa.n().to_vec());
        }
        Ok(len)
    }

    /// Retrieves the RSA public exponent (e) from the public key.
    ///
    /// This method can either return the required buffer size (when `e` is `None`)
    /// or copy the exponent to the provided buffer (when `e` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `e` - Optional output buffer for the exponent
    ///
    /// # Returns
    ///
    /// The size of the exponent in bytes (typically 3 bytes for value 65537).
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffer is too small.
    fn e(&self, e: Option<&mut [u8]>) -> Result<usize, CryptoError> {
        let rsa = self.key.rsa().map_err(|_| CryptoError::EccError)?;
        let len = rsa.e().num_bytes() as usize;
        if let Some(e) = e {
            if e.len() < len {
                return Err(CryptoError::EccBufferTooSmall);
            }
            e[..len].copy_from_slice(&rsa.e().to_vec());
        }
        Ok(len)
    }
}

impl OsslRsaPublicKey {
    /// Creates a new public key wrapper from an OpenSSL RSA key.
    ///
    /// This is an internal constructor used to wrap an existing OpenSSL key.
    ///
    /// # Arguments
    ///
    /// * `key` - An OpenSSL RSA public key
    ///
    /// # Returns
    ///
    /// A new `OsslRsaPublicKey` instance wrapping the provided key.
    fn new(key: PKey<Public>) -> Self {
        Self { key }
    }

    /// Returns a reference to the underlying OpenSSL public key.
    ///
    /// This is an internal method used by other cryptographic operations that
    /// need direct access to the OpenSSL key structure.
    ///
    /// # Returns
    ///
    /// A reference to the OpenSSL `PKey<Public>` wrapper.
    pub(crate) fn pkey(&self) -> &PKeyRef<Public> {
        &self.key
    }
}

/// Validates whether the given key size is supported.
///
/// This method checks if the key size is one of the standard RSA sizes
/// supported by this implementation.
///
/// # Arguments
///
/// * `size` - Key size in bytes to validate
///
/// # Returns
///
/// `true` if the size is valid (256, 384, or 512 bytes), `false` otherwise.
///
/// # Valid Sizes
///
/// - 256 bytes (2048 bits) - Minimum recommended
/// - 384 bytes (3072 bits) - Enhanced security
/// - 512 bytes (4096 bits) - High security
fn is_valid_key_size(size: usize) -> bool {
    matches!(size, 256 | 384 | 512)
}
