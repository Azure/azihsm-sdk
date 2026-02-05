// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Elliptic Curve Cryptography (ECC) operations.
//!
//! This module provides a comprehensive interface for elliptic curve cryptographic
//! operations including key generation, digital signatures (ECDSA), and key agreement
//! (ECDH). The implementation abstracts over platform-specific backends to provide
//! consistent APIs across different operating systems.
//!
//! # Supported Curves
//!
//! - **P-256 (secp256r1)**: 256-bit security, recommended for most applications
//! - **P-384 (secp384r1)**: 384-bit security, for high-security applications
//! - **P-521 (secp521r1)**: 521-bit security, maximum security level
//!
//! # Features
//!
//! - **Key Generation**: Generate ECC key pairs with secure randomness
//! - **ECDSA**: Digital signature creation and verification
//! - **ECDH**: Elliptic Curve Diffie-Hellman key agreement
//! - **Key Import/Export**: Serialize and deserialize keys in various formats
//! - **DER Support**: Encode and decode keys in DER format per RFC 5915
//!
//! # Platform Support
//!
//! - **Linux**: Uses OpenSSL implementations via the `ecc_ossl`, `key_ossl`, `ecdh_ossl` modules
//! - **Windows**: Uses Windows CNG via the `ecc_cng`, `key_cng`, `ecdh_cng` modules
//!
//! # Architecture
//!
//! The module is structured around several key components:
//!
//! - [`EccCurve`]: Enumeration of supported NIST curves
//! - [`EccPrivateKey`]: Platform-specific private key type
//! - [`EccPublicKey`]: Platform-specific public key type
//! - [`Ecc`]: Core ECC operations (signing, verification)
//! - [`Ecdh`]: Key agreement operations
//! - [`Ecdsa`]: ECDSA signature operations with hash integration
//!
//! # Security Considerations
//!
//! - Private keys must be kept secure and never exposed
//! - Use cryptographically secure random sources for key generation
//! - Curve selection should match security requirements (P-256 minimum recommended)
//! - ECDSA signatures may be deterministic depending on implementation
//! - ECDH shared secrets should be used with KDFs, never directly as keys
cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod key_ossl;
        mod ecc_ossl;
        mod ecdh_ossl;
    } else if #[cfg(target_os = "windows")] {
        mod key_cng;
        mod ecc_cng;
        mod ecdh_cng;
    } else {
        compile_error!("Unsupported target OS for AES-CBC implementation");
    }
}
mod ecdsa;

pub use ecdsa::EcdsaAlgo;
pub use ecdsa::EcdsaAlgoSignContext;
pub use ecdsa::EcdsaAlgoVerifyContext;

use super::*;

/// Enumeration of supported elliptic curves.
///
/// This enum represents the NIST-standardized elliptic curves supported
/// by the cryptographic library. Each curve provides a different security
/// level and performance characteristic.
///
/// # Security Levels
///
/// - **P-256**: Provides approximately 128-bit security strength
/// - **P-384**: Provides approximately 192-bit security strength
/// - **P-521**: Provides approximately 256-bit security strength
///
/// # Curve Selection
///
/// Choose curves based on security requirements:
/// - P-256: General purpose, widely supported, good performance
/// - P-384: High security applications, regulatory compliance
/// - P-521: Maximum security, specialized applications
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EccCurve {
    /// NIST P-256 curve (secp256r1).
    ///
    /// 256-bit prime field curve providing approximately 128-bit security strength.
    /// This is the most widely supported curve and recommended for general use.
    P256,

    /// NIST P-384 curve (secp384r1).
    ///
    /// 384-bit prime field curve providing approximately 192-bit security strength.
    /// Suitable for high-security applications and regulatory compliance.
    P384,

    /// NIST P-521 curve (secp521r1).
    ///
    /// 521-bit prime field curve providing approximately 256-bit security strength.
    /// Maximum security level, used in specialized applications.
    P521,
}

impl EccCurve {
    /// Returns the coordinate size in bytes for the curve.
    ///
    /// Each curve point coordinate (x or y) has a fixed size determined
    /// by the curve parameters:
    /// - P-256: 32 bytes
    /// - P-384: 48 bytes
    /// - P-521: 66 bytes (note: 521 bits rounded up to byte boundary)
    pub fn point_size(&self) -> usize {
        match self {
            EccCurve::P256 => 32,
            EccCurve::P384 => 48,
            EccCurve::P521 => 66,
        }
    }

    /// Returns the bit size of the curve.
    ///
    /// This returns the size of the underlying prime field in bits,
    /// which determines the security strength of the curve:
    /// - P-256: 256 bits
    /// - P-384: 384 bits
    /// - P-521: 521 bits
    pub fn bit_size(&self) -> usize {
        match self {
            EccCurve::P256 => 256,
            EccCurve::P384 => 384,
            EccCurve::P521 => 521,
        }
    }
}

/// Converts a curve bit size to an ECC curve identifier.
///
/// This trait implementation allows constructing curve identifiers from
/// their bit sizes, which is useful when working with external APIs or
/// configuration that specifies curve sizes numerically.
///
/// # Errors
///
/// Returns `CryptoError::EccInvalidKeySize` if the bit size does not match
/// any supported curve (must be exactly 256, 384, or 521).
impl TryFrom<usize> for EccCurve {
    type Error = CryptoError;

    fn try_from(size: usize) -> Result<Self, Self::Error> {
        match size {
            256 => Ok(EccCurve::P256),
            384 => Ok(EccCurve::P384),
            521 => Ok(EccCurve::P521),
            _ => Err(CryptoError::EccInvalidKeySize),
        }
    }
}

/// Trait for ECC key-specific operations.
///
/// This trait provides methods for retrieving ECC-specific information
/// from key objects, including the curve identifier and public key
/// coordinates. It's implemented by both private and public ECC keys.
///
/// # Coordinate Representation
///
/// ECC public keys are represented as points on the elliptic curve with
/// (x, y) coordinates. The coordinate size depends on the curve:
/// - P-256: 32 bytes per coordinate
/// - P-384: 48 bytes per coordinate
/// - P-521: 66 bytes per coordinate
pub trait EccKeyOp {
    /// Returns the elliptic curve used by this key.
    ///
    /// # Returns
    ///
    /// The `EccCurve` identifier (P256, P384, or P521).
    fn curve(&self) -> EccCurve;

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
    fn coord(&self, coord: Option<(&mut [u8], &mut [u8])>) -> Result<usize, CryptoError>;

    /// Retrieves the X and Y coordinates as separate vectors.
    ///
    /// This is a convenience method that allocates vectors for the coordinates
    /// and calls `coord()` to fill them.
    ///
    /// # Returns
    ///
    /// A tuple `(x, y)` containing the X and Y coordinates as byte vectors,
    /// each of size `curve().point_size()`.
    ///
    /// # Errors
    ///
    /// Returns errors if coordinate extraction fails.
    fn coord_vec(&self) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let coord_size = self.curve().point_size();
        let mut x_buf = vec![0u8; coord_size];
        let mut y_buf = vec![0u8; coord_size];
        let written_size = self.coord(Some((&mut x_buf, &mut y_buf)))?;
        debug_assert!(written_size == coord_size);
        Ok((x_buf, y_buf))
    }
}

define_type!(pub EccPrivateKey, key_ossl::OsslEccPrivateKey, key_cng::CngEccPrivateKey);
define_type!(pub EccPublicKey, key_ossl::OsslEccPublicKey, key_cng::CngEccPublicKey);
define_type!(pub EccAlgo, ecc_ossl::OsslEccAlgo, ecc_cng::CngEccAlgo);
define_type!(pub EcdhAlgo<'a>, ecdh_ossl::OsslEcdhAlgo<'a>, ecdh_cng::CngEcdhAlgo<'a>);

#[cfg(test)]
mod tests;
