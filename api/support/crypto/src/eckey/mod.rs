// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! ECC (Elliptic Curve Cryptography) module for cross-platform key management and operations.

#[cfg(target_os = "windows")]
mod eckey_cng;
#[cfg(target_os = "linux")]
mod eckey_ossl;

use std::sync::Arc;
use std::sync::Mutex;

#[cfg(target_os = "windows")]
use eckey_cng::CngPrivateKeyHandle;
#[cfg(target_os = "windows")]
use eckey_cng::CngPublicKeyHandle;
#[cfg(target_os = "linux")]
use eckey_ossl::OsslPrivateKeyHandle;
#[cfg(target_os = "linux")]
use eckey_ossl::OsslPublicKeyHandle;

use crate::CryptoError;
use crate::HashAlgo;

/// Supported elliptic curve identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurveId {
    /// NIST P-256 (secp256r1)
    EccP256,
    /// NIST P-384 (secp384r1)
    EccP384,
    /// NIST P-521 (secp521r1)
    EccP521,
}
impl EcCurveId {
    /// Returns the degree (bit size) for a given [`EcCurveId`].
    ///
    /// # Arguments
    /// * `curve` - The elliptic curve identifier.
    ///
    /// # Returns
    /// The bit size of the curve (e.g., 256, 384, 521).
    pub fn curve_degree(&self) -> u32 {
        match self {
            EcCurveId::EccP256 => 256,
            EcCurveId::EccP384 => 384,
            EcCurveId::EccP521 => 521,
        }
    }

    /// Returns the [`EcCurveId`] corresponding to the given curve degree in bits, if supported.
    ///
    /// # Arguments
    /// * `bits` - The bit size of the curve (e.g., 256, 384, 521).
    ///
    /// # Returns
    /// An [`Option<EcCurveId>`] corresponding to the curve, or `None` if not supported.
    pub fn from_bits(bits: u32) -> Option<Self> {
        match bits {
            256 => Some(EcCurveId::EccP256),
            384 => Some(EcCurveId::EccP384),
            521 => Some(EcCurveId::EccP521),
            _ => None,
        }
    }

    /// Returns true if the hash algorithm is supported for the given EC curve degree.
    ///
    /// # Arguments
    /// * `curve_degree` - The bit size of the curve (e.g., 256, 384, 521).
    /// * `algo` - The hash algorithm to check.
    ///
    /// # Returns
    /// `true` if the hash algorithm is valid for the curve, `false` otherwise.
    pub fn is_hash_supported_for_curve(&self, algo: HashAlgo) -> bool {
        self.valid_hash_algos_for_curve().contains(&algo)
    }
    /// Returns the valid hash algorithms for a given EcCurveId.
    ///
    /// # Returns
    /// A `Vec<HashAlgo>` containing the supported hash algorithms for this curve.
    pub fn valid_hash_algos_for_curve(&self) -> Vec<HashAlgo> {
        match self {
            EcCurveId::EccP256 => vec![HashAlgo::Sha256],
            EcCurveId::EccP384 => vec![HashAlgo::Sha384],
            EcCurveId::EccP521 => vec![HashAlgo::Sha512],
        }
    }
    /// Returns if the size of digest is valid for the curve or not .
    ///
    /// # Returns
    /// A `bool` true if size of the hash is expected for the curve or false if not .
    pub fn is_digest_valid_for_curve(&self, digest: &[u8]) -> bool {
        for algo in self.valid_hash_algos_for_curve() {
            let expected_size = match algo {
                HashAlgo::Sha256 => 32,
                HashAlgo::Sha384 => 48,
                HashAlgo::Sha512 => 64,
                HashAlgo::Sha1 => {
                    tracing::error!("SHA-1 is not supported for ECC curve digest size validation");
                    return false;
                }
            };
            // For P-521, digest is typically 66 bytes (521 bits rounded up), but hash output is 64 bytes (SHA-512)
            if *self == EcCurveId::EccP521 && algo == HashAlgo::Sha512 {
                if digest.len() == 66 || digest.len() == 64 {
                    return true;
                }
            } else if digest.len() == expected_size {
                return true;
            }
        }
        false
    }
}

/// ECC private key wrapper for platform-specific handle.
#[derive(Clone)]
pub struct EcPrivateKey {
    #[cfg(target_os = "linux")]
    /// OpenSSL private key handle (Linux)
    pub private_key_handle: Arc<Mutex<OsslPrivateKeyHandle>>,
    #[cfg(target_os = "windows")]
    /// CNG private key handle (Windows)
    pub private_key_handle: Arc<Mutex<CngPrivateKeyHandle>>,
}

/// ECC public key wrapper for platform-specific handle.
#[derive(Clone)]
pub struct EcPublicKey {
    #[cfg(target_os = "linux")]
    /// OpenSSL public key handle (Linux)
    pub public_key_handle: Arc<Mutex<OsslPublicKeyHandle>>,
    #[cfg(target_os = "windows")]
    /// CNG public key handle (Windows)
    pub public_key_handle: Arc<Mutex<CngPublicKeyHandle>>,
}

// Key related operations
/// Trait for ECC key operations such as DER serialization and size queries.
pub trait EckeyOps<T> {
    /// Loads a key from DER encoding for the given curve.
    fn ec_key_from_der(der: &[u8], curveid: EcCurveId) -> Result<T, CryptoError>;
    /// Serializes the key to DER encoding.
    fn ec_key_to_der(&self, der: &mut [u8]) -> Result<usize, CryptoError>;
    /// Returns the degree (size in bits) of the curve.
    fn size(&self) -> Result<usize, CryptoError>;
}

/// Trait for ECC key pair generation.
pub trait EcKeyGenOp {
    /// Generates a new ECC private/public key pair for the specified curve.
    fn ec_key_gen_pair(
        &self,
        curve_id: EcCurveId,
    ) -> Result<(EcPrivateKey, EcPublicKey), CryptoError>;
}

/// Marker struct for ECC key generation operations.
pub struct EcKeyGen;

#[cfg(test)]
pub mod eckey_test_vectors;

#[cfg(test)]
mod tests {
    use eckey_test_vectors::*;
    use test_log::test;

    use super::*;

    // Helper: all supported curves
    const CURVES: [EcCurveId; 3] = [EcCurveId::EccP256, EcCurveId::EccP384, EcCurveId::EccP521];

    #[test]
    /// Tests that key generation produces matching private and public key sizes, and matches the expected curve degree.
    fn test_key_generation_and_curve_degree() {
        for &curve in &CURVES {
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).expect("keygen");
            let deg_priv = priv_key.size().unwrap();
            let deg_pub = pub_key.size().unwrap();
            assert_eq!(deg_priv, deg_pub);
            // Compare all in bytes
            assert_eq!(deg_priv, curve.curve_degree() as usize);
        }
    }

    #[test]
    /// Tests that a public key can be DER-encoded and decoded (roundtrip) without loss of information.
    fn test_public_key_der_roundtrip() {
        for &curve in &CURVES {
            let (_priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let mut der = vec![0u8; 256];
            let len = pub_key.ec_key_to_der(&mut der).unwrap();
            let der = &der[..len];
            let pub2 = EcPublicKey::ec_key_from_der(der, curve).unwrap();
            let mut der2 = vec![0u8; 256];
            let len2 = pub2.ec_key_to_der(&mut der2).unwrap();
            assert_eq!(der, &der2[..len2]);
        }
    }

    #[test]
    /// Tests that private key export works on both Windows and Linux, and roundtrips correctly.
    fn test_private_key_import_and_export_roundtrip() {
        // Private key export is now supported on both Windows (CNG) and Linux (OpenSSL)
        for &curve in &CURVES {
            let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let mut der = vec![0u8; 512]; // Increased buffer size for private keys
            let res = priv_key.ec_key_to_der(&mut der);

            assert!(
                res.is_ok(),
                "Private key export should work on both platforms for curve {:?}",
                curve
            );
            let len = res.unwrap();
            let exported_der = &der[..len];

            // Test roundtrip: import the exported private key
            let imported = EcPrivateKey::ec_key_from_der(exported_der, curve)
                .expect("Should be able to import exported private key");

            // Test that we can export the imported key again and get the same result
            let mut der2 = vec![0u8; 512];
            let len2 = imported.ec_key_to_der(&mut der2).unwrap();
            let exported_der2 = &der2[..len2];

            // The DER exports should be identical
            assert_eq!(
                exported_der, exported_der2,
                "Roundtrip export should produce identical DER for curve {:?}",
                curve
            );
        }
    }

    #[test]
    /// Imports NIST test vectors and checks that private and public keys can be parsed.
    ///
    /// Coverage: Key import for all supported curves and vector types.
    fn test_nist_key_import() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[test_nist_key_import] vector index: {}, curve: {:?}",
                i, vector.curve
            );
            let priv_key = match EcPrivateKey::ec_key_from_der(vector.private_key_der, vector.curve)
            {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] private ec_key_from_der failed: {:?}", i, e);
                    panic!("private ec_key_from_der failed");
                }
            };
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(pk) => pk,
                Err(e) => {
                    println!("  [vector {}] public ec_key_from_der failed: {:?}", i, e);
                    panic!("public ec_key_from_der failed");
                }
            };
            assert_eq!(
                priv_key.size().unwrap(),
                vector.curve.curve_degree() as usize
            );
            assert_eq!(
                pub_key.size().unwrap(),
                vector.curve.curve_degree() as usize
            );
        }
    }
}
