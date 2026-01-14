// Copyright (C) Microsoft Corporation. All rights reserved.

//! OpenSSL-based Elliptic Curve Cryptography (ECC) key operations.
//!
//! This module provides ECC private and public key implementations using OpenSSL
//! as the underlying cryptographic backend. It supports NIST standard curves
//! (P-256, P-384, P-521) for key generation, import, and export operations.
//!
//! # Supported Curves
//!
//! - **P-256** (secp256r1, prime256v1): 256-bit curve, 32-byte keys
//! - **P-384** (secp384r1): 384-bit curve, 48-byte keys
//! - **P-521** (secp521r1): 521-bit curve, 66-byte keys
//!
//! # Key Formats
//!
//! Keys are imported and exported in DER encoding format:
//! - Private keys: SEC1 ECPrivateKey format (RFC 5915)
//! - Public keys: X.509 SubjectPublicKeyInfo format
//!
//! # Security Considerations
//!
//! - Private keys should be stored securely and never transmitted unencrypted
//! - Use appropriate key sizes based on security requirements (P-256 minimum for new applications)
//! - Public keys can be freely distributed for signature verification and encryption
//! - Key generation uses cryptographically secure random number generation

use openssl::bn::*;
use openssl::ec::*;
use openssl::nid::*;
use openssl::pkey::*;

use super::*;

/// OpenSSL ECC private key implementation.
///
/// This structure wraps an OpenSSL ECC private key and provides operations for
/// key generation, import, export, and public key derivation. Private keys contain
/// both the private scalar and the public point on the elliptic curve.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's ECC key operations are thread-safe.
///
/// # Security
///
/// Private keys should be:
/// - Protected from unauthorized access
/// - Securely zeroed when no longer needed
/// - Never transmitted or stored without encryption
/// - Generated using cryptographically secure random sources
#[derive(Debug, Clone)]
pub struct OsslEccPrivateKey {
    /// The underlying OpenSSL ECC private key
    key: PKey<Private>,
    curve: EccCurve,
}

/// OpenSSL ECC public key implementation.
///
/// This structure wraps an OpenSSL ECC public key and provides operations for
/// key import and export. Public keys represent a point on the elliptic curve
/// and can be freely distributed for signature verification and encryption.
///
/// # Thread Safety
///
/// This structure is `Send` and `Sync` as OpenSSL's ECC key operations are thread-safe.
///
/// # Security
///
/// Public keys:
/// - Can be freely transmitted and stored
/// - Should be authenticated to prevent man-in-the-middle attacks
/// - Are derived from private keys and cannot be reversed to obtain the private key
#[derive(Debug, Clone)]
pub struct OsslEccPublicKey {
    /// The underlying OpenSSL ECC public key
    key: PKey<Public>,
    curve: EccCurve,
}

/// Marks this type as a cryptographic key.
impl Key for OsslEccPrivateKey {
    /// Returns the length of the ECC private key in bytes.
    ///
    /// The size corresponds to the curve:
    /// - P-256: 32 bytes
    /// - P-384: 48 bytes
    /// - P-521: 66 bytes
    fn size(&self) -> usize {
        self.key.size()
    }

    /// Returns the length of the ECC private key in bits.
    ///
    /// The bit size corresponds to the curve:
    /// - P-256: 256 bits
    /// - P-384: 384 bits
    /// - P-521: 521 bits
    fn bits(&self) -> usize {
        self.key.bits() as usize
    }
}

/// Marks this type as a signing key for ECDSA operations.
///
/// ECC private keys can create digital signatures that authenticate messages
/// and prove the identity of the signer.
impl SigningKey for OsslEccPrivateKey {}

/// Marks this type as a key usable in derivation operations.
///
/// ECC private keys can be used in key agreement protocols like ECDH to
/// derive shared secrets with a peer's public key.
impl DerivationKey for OsslEccPrivateKey {}

impl PrivateKey for OsslEccPrivateKey {
    type PublicKey = OsslEccPublicKey;

    /// Derives the public key from this private key.
    ///
    /// This method extracts the public point from the private key. The operation
    /// is deterministic and always produces the same public key for a given private key.
    ///
    /// # Returns
    ///
    /// The corresponding public key on success.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccError` if the public key extraction fails.
    fn public_key(&self) -> Result<Self::PublicKey, CryptoError> {
        let key = self.key.ec_key().map_err(|_| CryptoError::EccError)?;
        let group = key.group();
        let ec_key =
            EcKey::from_public_key(group, key.public_key()).map_err(|_| CryptoError::EccError)?;
        let pkey = PKey::from_ec_key(ec_key).map_err(|_| CryptoError::EccError)?;
        let nid = group.curve_name().ok_or(CryptoError::EccError)?;
        let curve = nid.try_into()?;
        Ok(OsslEccPublicKey::new(pkey, curve))
    }
}

/// Marks this key as importable.
impl ImportableKey for OsslEccPrivateKey {
    /// Imports an ECC private key from DER-encoded bytes.
    ///
    /// This method parses a DER-encoded private key in SEC1 ECPrivateKey format
    /// (RFC 5915). The key must be properly formatted and contain a valid curve
    /// identifier and private scalar.
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
    /// - The curve is not supported
    /// - The private key value is invalid for the curve
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let pkey =
            PKey::private_key_from_pkcs8(bytes).map_err(|_| CryptoError::EccKeyImportError)?;
        let eckey = pkey.ec_key().map_err(|_| CryptoError::EccError)?;
        let nid = eckey.group().curve_name().ok_or(CryptoError::EccError)?;
        let curve = nid.try_into()?;
        Ok(OsslEccPrivateKey::new(pkey, curve))
    }
}

impl ExportableKey for OsslEccPrivateKey {
    /// Exports this ECC private key to DER-encoded bytes.
    ///
    /// This method encodes the private key in SEC1 ECPrivateKey format (RFC 5915),
    /// including the curve identifier and private scalar. The public key may also
    /// be included in the encoding.
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

impl KeyGenerationOp for OsslEccPrivateKey {
    type Key = Self;

    /// Generates a new ECC private key for the specified key size.
    ///
    /// This method generates a cryptographically secure random private key
    /// for the curve corresponding to the given size. The key generation uses
    /// OpenSSL's secure random number generator.
    ///
    /// # Arguments
    ///
    /// * `size` - Key size in bytes:
    ///   - 32 bytes for P-256 (secp256r1)
    ///   - 48 bytes for P-384 (secp384r1)
    ///   - 66 bytes for P-521 (secp521r1)
    ///
    /// # Returns
    ///
    /// A new randomly generated private key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccInvalidKeySize` - The size does not match a supported curve
    /// - `CryptoError::EccError` - Curve initialization fails
    /// - `CryptoError::EccKeyGenError` - Key generation fails
    ///
    /// # Security
    ///
    /// Generated keys use cryptographically secure randomness and are suitable
    /// for production use.
    fn generate(size: usize) -> Result<Self, CryptoError> {
        let nid = Nid::try_from(EccKeySize(size))?;
        let group = EcGroup::from_curve_name(nid).map_err(|_| CryptoError::EccError)?;
        let ec_key = EcKey::generate(&group).map_err(|_| CryptoError::EccKeyGenError)?;
        let pkey = PKey::from_ec_key(ec_key).map_err(|_| CryptoError::EccError)?;
        let curve = nid.try_into()?;
        Ok(OsslEccPrivateKey::new(pkey, curve))
    }
}

impl EccKeyOp for OsslEccPrivateKey {
    /// Returns the elliptic curve used by this private key.
    ///
    /// # Returns
    ///
    /// The `EccCurve` identifier (P256, P384, or P521).
    fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Retrieves the X and Y coordinates of the public key point.
    ///
    /// This method can either return the required buffer size (when `coord` is `None`)
    /// or copy the coordinates to the provided buffers (when `coord` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `coord` - Optional tuple of mutable buffers for (x, y) coordinates.
    ///
    /// # Returns
    ///
    /// The size of each coordinate in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffers are too small.
    fn coord(&self, coord: Option<(&mut [u8], &mut [u8])>) -> Result<usize, CryptoError> {
        let coord_size = self.curve().point_size();
        if let Some((x_buf, y_buf)) = coord {
            if x_buf.len() < coord_size || y_buf.len() < coord_size {
                return Err(CryptoError::EccBufferTooSmall);
            }
            let (x, y) = self.coordinates()?;
            x_buf[..coord_size].copy_from_slice(&x[..coord_size]);
            y_buf[..coord_size].copy_from_slice(&y[..coord_size]);
        }
        Ok(coord_size)
    }
}

impl OsslEccPrivateKey {
    /// Creates a new private key wrapper from an OpenSSL ECC key.
    ///
    /// This is an internal constructor used to wrap an existing OpenSSL key.
    ///
    /// # Arguments
    ///
    /// * `key` - An OpenSSL ECC private key
    ///
    /// # Returns
    ///
    /// A new `OsslEccPrivateKey` instance wrapping the provided key.
    fn new(key: PKey<Private>, curve: EccCurve) -> Self {
        Self { key, curve }
    }

    /// Generates a new ECC private key for the specified curve.
    ///
    /// This is a convenience method that generates a key using the curve enum
    /// rather than a numeric size.
    ///
    /// # Arguments
    ///
    /// * `curve` - The elliptic curve to use (P256, P384, or P521)
    ///
    /// # Returns
    ///
    /// A new randomly generated private key on success.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `CryptoError::EccError` - Curve initialization fails
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

    /// Extracts both X and Y coordinates of the public key point.
    ///
    /// This is an internal helper method that retrieves the affine coordinates
    /// of the public point in big-endian byte format, zero-padded to the full
    /// coordinate size for the curve.
    ///
    /// # Returns
    ///
    /// A tuple `(x, y)` containing the X and Y coordinates as byte vectors.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccError` if:
    /// - Curve determination fails
    /// - BigNum context creation fails
    /// - Coordinate extraction fails
    /// - Byte conversion fails
    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let len: usize = self.curve().into();
        let key = self.key.ec_key().map_err(|_| CryptoError::EccError)?;
        let group = key.group();
        let point = key.public_key();
        let mut ctx = BigNumContext::new().map_err(|_| CryptoError::EccError)?;

        let mut x = BigNum::new().map_err(|_| CryptoError::EccError)?;
        let mut y = BigNum::new().map_err(|_| CryptoError::EccError)?;

        point
            .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
            .map_err(|_| CryptoError::EccError)?;

        let x = x
            .to_vec_padded(len as i32)
            .map_err(|_| CryptoError::EccError)?;
        let y = y
            .to_vec_padded(len as i32)
            .map_err(|_| CryptoError::EccError)?;

        Ok((x, y))
    }
}

/// Marks this type as a cryptographic key.
impl Key for OsslEccPublicKey {
    /// Returns the length of the ECC public key in bytes.
    ///
    /// The size corresponds to the curve:
    /// - P-256: 32 bytes
    /// - P-384: 48 bytes
    /// - P-521: 66 bytes
    fn size(&self) -> usize {
        self.key.size()
    }

    /// Returns the length of the ECC public key in bits.
    ///
    /// The bit size corresponds to the curve:
    /// - P-256: 256 bits
    /// - P-384: 384 bits
    /// - P-521: 521 bits
    fn bits(&self) -> usize {
        self.key.bits() as usize
    }
}

/// Marks this type as a verification key for ECDSA operations.
///
/// ECC public keys can verify digital signatures created by the corresponding
/// private key, ensuring message authenticity and integrity.
impl VerificationKey for OsslEccPublicKey {}

/// Marks this type as an asymmetric public key.
///
/// Public keys can be freely distributed and used for signature verification
/// and in key agreement protocols.
impl PublicKey for OsslEccPublicKey {}

/// Marks this key as importable.
impl ImportableKey for OsslEccPublicKey {
    /// Imports an ECC public key from DER-encoded bytes.
    ///
    /// This method parses a DER-encoded public key in X.509 SubjectPublicKeyInfo
    /// format. The key must be properly formatted and contain a valid curve
    /// identifier and public point.
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
    /// - The curve is not supported
    /// - The public point is not on the curve
    /// - The point encoding is invalid
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key = EcKey::public_key_from_der(bytes).map_err(|_| CryptoError::EccKeyImportError)?;
        let nid = key.group().curve_name().ok_or(CryptoError::EccError)?;
        let pkey = PKey::from_ec_key(key).map_err(|_| CryptoError::EccError)?;
        let curve = nid.try_into()?;
        Ok(OsslEccPublicKey::new(pkey, curve))
    }
}

/// Marks this key as exportable.
impl ExportableKey for OsslEccPublicKey {
    /// Exports this ECC public key to DER-encoded bytes.
    ///
    /// This method encodes the public key in X.509 SubjectPublicKeyInfo format,
    /// including the curve identifier and public point coordinates.
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

impl OsslEccPublicKey {
    /// Creates a new public key wrapper from an OpenSSL ECC key.
    ///
    /// This is an internal constructor used to wrap an existing OpenSSL key.
    ///
    /// # Arguments
    ///
    /// * `key` - An OpenSSL ECC public key
    ///
    /// # Returns
    ///
    /// A new `OsslEccPublicKey` instance wrapping the provided key.
    fn new(key: PKey<Public>, curve: EccCurve) -> Self {
        Self { key, curve }
    }

    /// Returns the elliptic curve used by this public key.
    ///
    /// This method extracts the curve identifier from the key and converts it
    /// to the EccCurve enum.
    ///
    /// # Returns
    ///
    /// The curve enum (P256, P384, or P521) on success.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccError` if:
    /// - The curve name cannot be determined
    /// - The curve is not one of the supported NIST curves
    pub fn curve(&self) -> EccCurve {
        self.curve
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

    /// Extracts both X and Y coordinates of the public key point.
    ///
    /// This is an internal helper method that retrieves the affine coordinates
    /// of the public point in big-endian byte format, zero-padded to the full
    /// coordinate size for the curve.
    ///
    /// # Returns
    ///
    /// A tuple `(x, y)` containing the X and Y coordinates as byte vectors.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccError` if:
    /// - Curve determination fails
    /// - BigNum context creation fails
    /// - Coordinate extraction fails
    /// - Byte conversion fails
    fn coordinates(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let len: usize = self.curve().into();
        let key = self.key.ec_key().map_err(|_| CryptoError::EccError)?;
        let group = key.group();
        let point = key.public_key();
        let mut ctx = BigNumContext::new().map_err(|_| CryptoError::EccError)?;

        let mut x = BigNum::new().map_err(|_| CryptoError::EccError)?;
        let mut y = BigNum::new().map_err(|_| CryptoError::EccError)?;

        point
            .affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)
            .map_err(|_| CryptoError::EccError)?;

        let x = x
            .to_vec_padded(len as i32)
            .map_err(|_| CryptoError::EccError)?;
        let y = y
            .to_vec_padded(len as i32)
            .map_err(|_| CryptoError::EccError)?;

        Ok((x, y))
    }
}

impl EccKeyOp for OsslEccPublicKey {
    /// Returns the elliptic curve used by this public key.
    ///
    /// # Returns
    ///
    /// The `EccCurve` identifier (P256, P384, or P521).
    fn curve(&self) -> EccCurve {
        self.curve
    }

    /// Retrieves the X and Y coordinates of the public key point.
    ///
    /// This method can either return the required buffer size (when `coord` is `None`)
    /// or copy the coordinates to the provided buffers (when `coord` is `Some`).
    ///
    /// # Arguments
    ///
    /// * `coord` - Optional tuple of mutable buffers for (x, y) coordinates.
    ///
    /// # Returns
    ///
    /// The size of each coordinate in bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccBufferTooSmall` if the provided buffers are too small.
    fn coord(&self, coord: Option<(&mut [u8], &mut [u8])>) -> Result<usize, CryptoError> {
        let coord_size = self.curve().point_size();
        if let Some((x_buf, y_buf)) = coord {
            if x_buf.len() < coord_size || y_buf.len() < coord_size {
                return Err(CryptoError::EccBufferTooSmall);
            }
            let (x, y) = self.coordinates()?;
            x_buf[..coord_size].copy_from_slice(&x[..coord_size]);
            y_buf[..coord_size].copy_from_slice(&y[..coord_size]);
        }
        Ok(coord_size)
    }
}

/// Converts an ECC curve enum to an OpenSSL NID (Numeric Identifier).
///
/// This conversion maps the curve enum values to their corresponding OpenSSL
/// curve identifiers used for key generation and operations.
impl From<EccCurve> for Nid {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::P256 => Nid::X9_62_PRIME256V1,
            EccCurve::P384 => Nid::SECP384R1,
            EccCurve::P521 => Nid::SECP521R1,
        }
    }
}

/// Internal wrapper for ECC key sizes used in conversion to OpenSSL NIDs.
///
/// This structure wraps a key size in bytes and provides conversion to the
/// corresponding OpenSSL curve identifier.
struct EccKeySize(usize);

/// Converts an ECC key size to an OpenSSL NID.
///
/// This conversion maps key sizes to their corresponding OpenSSL curve identifiers:
/// - 32 bytes → P-256 (secp256r1)
/// - 48 bytes → P-384 (secp384r1)
/// - 66 bytes → P-521 (secp521r1)
impl TryFrom<EccKeySize> for Nid {
    type Error = CryptoError;

    /// Converts a key size to the corresponding OpenSSL curve NID.
    ///
    /// # Arguments
    ///
    /// * `size` - Key size wrapper containing the size in bytes
    ///
    /// # Returns
    ///
    /// The OpenSSL NID for the corresponding curve.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccInvalidKeySize` if the size does not match
    /// any supported curve (must be 32, 48, or 66 bytes).
    fn try_from(size: EccKeySize) -> Result<Self, Self::Error> {
        match size.0 {
            32 => Ok(Nid::X9_62_PRIME256V1),
            48 => Ok(Nid::SECP384R1),
            66 => Ok(Nid::SECP521R1),
            _ => Err(CryptoError::EccInvalidKeySize),
        }
    }
}

/// Converts an ECC curve enum to its key size in bytes.
///
/// This conversion provides the private key size for each supported curve:
/// - P-256: 32 bytes
/// - P-384: 48 bytes
/// - P-521: 66 bytes
impl From<EccCurve> for usize {
    fn from(curve: EccCurve) -> Self {
        match curve {
            EccCurve::P256 => 32,
            EccCurve::P384 => 48,
            EccCurve::P521 => 66,
        }
    }
}

/// Converts an OpenSSL NID to an ECC curve enum.
///
/// This conversion maps OpenSSL curve identifiers to the EccCurve enum values.
impl TryFrom<Nid> for EccCurve {
    type Error = CryptoError;

    /// Converts an OpenSSL NID to the corresponding ECC curve enum.
    ///
    /// # Arguments
    ///
    /// * `nid` - OpenSSL numeric identifier for the curve
    ///
    /// # Returns
    ///
    /// The corresponding `EccCurve` enum value.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::EccInvalidKeySize` if the NID does not match
    /// any supported curve (must be P-256, P-384, or P-521).
    fn try_from(nid: Nid) -> Result<Self, Self::Error> {
        match nid {
            Nid::X9_62_PRIME256V1 => Ok(EccCurve::P256),
            Nid::SECP384R1 => Ok(EccCurve::P384),
            Nid::SECP521R1 => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccInvalidKeySize),
        }
    }
}
