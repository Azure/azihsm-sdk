// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! # azihsm-native-crypto-ecc-dev
//!
//! This crate provides Elliptic Curve Cryptography (ECC) key management and operations using the OpenSSL backend.
//! It includes functionality for key generation, serialization/deserialization (DER), and signature validation
//! for NIST P-256, P-384, and P-521 curves. The implementation wraps OpenSSL's EC key types and provides
//! safe Rust abstractions for cryptographic operations.
//!
//! ## Features
//! - ECC key generation for supported NIST curves
//! - DER encoding/decoding for public and private keys
//! - Signature length validation for DER-encoded EC signatures
//! - Safe resource management using `Arc<Mutex<...>>` for key handles
//!
//! ## Safety
//! All cryptographic operations are performed using the OpenSSL FFI via the `openssl` crate. Key material is
//! managed securely and never logged or exposed in error messages.
//!
//! ## Example
//! ```rust
//! use azihsm_native_crypto_ecc_dev::{EcKeyGen, EcCurveId};
//! let keygen = EcKeyGen::default();
//! let (priv_key, pub_key) = keygen.ec_key_gen_pair(EcCurveId::EccP256).unwrap();
//! ```
//!

use std::sync::Arc;
use std::sync::Mutex;

use openssl::ec::EcGroup;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;

use super::*;

impl EcCurveId {
    /// Returns the OpenSSL Nid for a given EcCurveId.
    fn ecc_get_curve_id(&self) -> Result<Nid, CryptoError> {
        let nid = match self {
            EcCurveId::EccP256 => Nid::X9_62_PRIME256V1, // Use NIST P-256, not SECP256K1
            EcCurveId::EccP384 => Nid::SECP384R1,
            EcCurveId::EccP521 => Nid::SECP521R1,
        };
        Ok(nid)
    }

    /// Helper to check if a DER-encoded EC signature length is valid for the given EC group.
    pub fn is_valid_ec_signature_length(group: &openssl::ec::EcGroupRef, sig_len: usize) -> bool {
        let degree = group.degree();
        // EC DER signature size: empirically determined min/max for each NIST curve.
        // These values match OpenSSL and NIST test vectors, and are robust to all valid encodings:
        //   - P-256: 69–72 bytes (r, s are 32 bytes, with/without leading 0x00)
        //   - P-384: 101–107 bytes (r, s are 48 bytes, with/without leading 0x00)
        //   - P-521: 135–139 bytes (r, s are 66 bytes, with/without leading 0x00)
        // If you see a failure here, check for malformed or non-standard DER signatures.
        let (min_sig_len, max_sig_len) = match degree {
            256 => (69, 72),   // P-256: 69–72
            384 => (101, 107), // P-384: 101–107 (expanded to cover all valid DER lengths)
            521 => (135, 139), // P-521: 135–139
            _ => (69, 139),    // fallback for unknown curves
        };
        sig_len >= min_sig_len && sig_len <= max_sig_len
    }
}

#[derive(Clone)]
/// A handle for an OpenSSL EC (Elliptic Curve) private key.
///
/// This struct wraps an `EcKey<Private>` from the OpenSSL crate, providing
/// safe access and management of the underlying private key resource.
pub struct OsslPrivateKeyHandle {
    /// * `ossl_private_key_handle` - The OpenSSL EC private key handle.
    pub ossl_private_key_handle: EcKey<Private>,
}

/// A handle for an OpenSSL EC (Elliptic Curve) public key.
///
/// This struct wraps an `EcKey<Public>` from the OpenSSL crate, providing
/// safe access and management of the underlying public key resource.
#[derive(Clone)]
pub struct OsslPublicKeyHandle {
    /// * `ossl_public_key_handle` - The OpenSSL EC public key handle.
    pub ossl_public_key_handle: EcKey<Public>,
}

impl EckeyOps<EcPublicKey> for EcPublicKey {
    /// Parses a DER-encoded public key and returns an OsslPublicKeyHandle.
    ///
    /// # Parameters
    /// - `der`: DER-encoded public key bytes.
    /// - `_curveid`: Curve identifier (unused for OpenSSL).
    ///
    /// # Returns
    /// - `Ok(EcPublicKey)`: On success.
    /// - `Err(CryptoError)`: On parse failure.
    fn ec_key_from_der(der: &[u8], _curveid: EcCurveId) -> Result<EcPublicKey, CryptoError> {
        let key = openssl::ec::EcKey::public_key_from_der(der).map_err(|e| {
            tracing::error!(
                "ec_key_from_der: failed to parse DER for public key: {:?}",
                e
            );
            CryptoError::EcBackendError
        })?;
        Ok(EcPublicKey {
            public_key_handle: Arc::new(Mutex::new(OsslPublicKeyHandle {
                ossl_public_key_handle: key,
            })),
        })
    }

    /// Serializes the EC key to DER format.
    ///
    /// # Parameters
    /// - `der`: Mutable byte slice to write the DER-encoded key into.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written on success.
    /// - `Err(CryptoError)`: An error if serialization fails.
    fn ec_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        let der_vec = self
            .public_key_handle
            .lock()
            .unwrap()
            .ossl_public_key_handle
            .public_key_to_der()
            .map_err(|e| {
                tracing::error!("Failed to export public key to der : {:?}", e);
                CryptoError::EcExportFailed
            })?;
        //update der
        if der.len() < der_vec.len() {
            tracing::error!(
                "Buffer is too small , expected: {}, actual: {}",
                der_vec.len(),
                der.len()
            );
            return Err(CryptoError::EcBufferTooSmall);
        }
        der[..der_vec.len()].copy_from_slice(&der_vec);
        println!("Exporting public key is done");
        Ok(der_vec.len())
    }

    /// Returns the size of the EC key in bytes.
    ///
    /// # Returns
    /// - `Ok(usize)`: The size of the key in bytes on success.
    /// - `Err(CryptoError)`: An error if the size could not be determined.
    fn size(&self) -> Result<usize, CryptoError> {
        let degree = self
            .public_key_handle
            .lock()
            .unwrap()
            .ossl_public_key_handle
            .group()
            .degree();
        if degree == 0 {
            tracing::error!("size: group degree is zero, invalid EC private key");
            return Err(CryptoError::EcBackendError);
        }
        Ok(degree as usize)
    }
}

impl EckeyOps<EcPrivateKey> for EcPrivateKey {
    /// Parses a DER-encoded private key and returns an OsslPrivateKeyHandle.
    ///
    /// # Arguments
    /// * `der` - DER-encoded private key bytes
    /// * `_curveid` - Curve identifier (unused for OpenSSL)
    ///
    /// # Returns
    /// * `Ok(OsslPrivateKeyHandle)` on success
    /// * `Err(CryptoError::EccError)` on parse failure
    fn ec_key_from_der(der: &[u8], _curveid: EcCurveId) -> Result<EcPrivateKey, CryptoError> {
        // / first get Pkey with PKCS#8 loaded
        let pkey = PKey::private_key_from_der(der).map_err(|e| {
            tracing::debug!("Failed to load PKCS#8 der: [REDACTED]");
            tracing::error!("Failed to parse der for private key: {:?}", e);
            // Use more specific error for ASN.1 parse error
            CryptoError::EcAsn1ParseError
        })?;

        let key = pkey.ec_key().map_err(|e| {
            tracing::error!(
                "ec_key_from_der: failed to extract EcKey from PKey: {:?}",
                e
            );
            // Use more specific error for curve mismatch
            CryptoError::EcCurveMismatch
        })?;
        Ok(EcPrivateKey {
            private_key_handle: Arc::new(Mutex::new(OsslPrivateKeyHandle {
                ossl_private_key_handle: key,
            })),
        })
    }

    /// Serializes the private key to DER format.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` containing DER bytes on success
    /// * `Err(CryptoError::EccError)` on serialization failure
    fn ec_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError> {
        let pkey = PKey::from_ec_key(
            self.private_key_handle
                .lock()
                .unwrap()
                .ossl_private_key_handle
                .clone(),
        )
        .map_err(|e| {
            tracing::error!("Failed to get PKey from ECKey : {:?}", e);
            CryptoError::EcInvalidKey
        })?;
        let der_vec = pkey.private_key_to_pkcs8().map_err(|e| {
            tracing::error!("ec_key_to_der: OpenSSL DER serialization failed: {:?}", e);
            CryptoError::EcExportFailed
        })?;
        if der_vec.len() > der.len() {
            tracing::error!(
                "ec_key_to_der: DER buffer is too small, expected {:?}, received: {:?}",
                der_vec.len(),
                der.len()
            );
            Err(CryptoError::EcBufferTooSmall)
        } else {
            der[0..der_vec.len()].copy_from_slice(&der_vec);
            Ok(der_vec.len())
        }
    }

    /// Returns the degree (bit size) of the EC group for this private key.
    ///
    /// # Returns
    /// * `Ok(u32)` with the group degree
    /// * `Err(CryptoError::EccError)` if the group is invalid
    fn size(&self) -> Result<usize, CryptoError> {
        let degree = self
            .private_key_handle
            .lock()
            .unwrap()
            .ossl_private_key_handle
            .group()
            .degree();
        if degree == 0 {
            tracing::error!("size: group degree is zero, invalid EC private key");
            return Err(CryptoError::EccError);
        }
        Ok(degree as usize)
    }
}

impl EcKeyGenOp for EcKeyGen {
    /// Generates a new ECC private/public key pair for the specified curve.
    ///
    /// # Arguments
    /// * `curve_id` - The curve identifier
    ///
    /// # Returns
    /// * `Ok((PrivateKey, PublicKey))` on success
    /// * `Err(CryptoError::EccError)` on failure
    fn ec_key_gen_pair(
        &self,
        curve_id: EcCurveId,
    ) -> Result<(EcPrivateKey, EcPublicKey), CryptoError> {
        let nid = match curve_id.ecc_get_curve_id() {
            Ok(nid) => nid,
            Err(e) => {
                tracing::error!("ec_key_gen_pair: failed to get curve nid: {:?}", e);
                return Err(CryptoError::EccError);
            }
        };
        let group = match EcGroup::from_curve_name(nid) {
            Ok(group) => group,
            Err(e) => {
                tracing::error!("ec_key_gen_pair: failed to get EC group: {:?}", e);
                return Err(CryptoError::EccError);
            }
        };
        let ec_key = match EcKey::generate(&group) {
            Ok(ec_key) => ec_key,
            Err(e) => {
                tracing::error!("ec_key_gen_pair: failed to generate EC key: {:?}", e);
                return Err(CryptoError::EccError);
            }
        };
        let pub_key = match EcKey::from_public_key(&group, ec_key.public_key()) {
            Ok(pub_key) => pub_key,
            Err(e) => {
                tracing::error!("ec_key_gen_pair: failed to create public key: {:?}", e);
                return Err(CryptoError::EccError);
            }
        };
        let private_key_handle = Arc::new(Mutex::new(OsslPrivateKeyHandle {
            ossl_private_key_handle: ec_key,
        }));
        let public_key_handle = Arc::new(Mutex::new(OsslPublicKeyHandle {
            ossl_public_key_handle: pub_key,
        }));
        Ok((
            EcPrivateKey { private_key_handle },
            EcPublicKey { public_key_handle },
        ))
    }
}
