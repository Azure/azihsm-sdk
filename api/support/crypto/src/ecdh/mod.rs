// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! Elliptic Curve Diffie-Hellman (ECDH) key agreement module.
//!
//! This module provides a cross-platform abstraction for ECDH key derivation, supporting both Windows (CNG) and Linux (OpenSSL) backends.
//! It defines the `EcdhKeyDeriveOp` trait for deriving shared secrets and querying the expected output size for a given EC key.
//! Platform-specific implementations ensure correct and secure ECDH operations for all supported NIST curves (P-256, P-384, P-521).

#[cfg(target_os = "windows")]
mod ecdh_cng;

#[cfg(target_os = "linux")]
mod ecdh_ossl;

use crate::eckey::EcPublicKey;
use crate::CryptoError;

/// Trait for Elliptic Curve Diffie-Hellman (ECDH) key derivation operations.
///
/// This trait defines methods for deriving a shared secret using ECDH and for querying
/// the expected size of the derived key.
pub trait EcdhKeyDeriveOp {
    /// Derives a shared secret using Elliptic Curve Diffie-Hellman (ECDH).
    ///
    /// # Arguments
    ///
    /// * `public_key` - Reference to the peer's public elliptic curve key (`EcPublicKey`).
    /// * `derived_key` - Mutable byte slice to store the derived shared secret.
    ///
    /// # Returns
    ///
    /// * `Ok(&[u8])` - A slice referencing the derived shared secret on success.
    /// * `Err(CryptoError)` - If key derivation fails.
    fn ecdh_key_derive<'a>(
        &self,
        public_key: &EcPublicKey,
        derived_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;

    /// Returns the size in bytes of the derived key for the current ECDH context.
    ///
    /// # Returns
    ///
    /// * `Ok(usize)` - The size of the derived key in bytes.
    /// * `Err(CryptoError)` - If the size cannot be determined.
    fn ecdh_get_derived_key_size(&self) -> Result<usize, CryptoError>;
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::eckey::*;

    const CURVES: [EcCurveId; 3] = [EcCurveId::EccP256, EcCurveId::EccP384, EcCurveId::EccP521];

    // Helper to generate a keypair for a given curve
    fn generate_keypair(curve: EcCurveId) -> (EcPrivateKey, EcPublicKey) {
        let (private_key, public_key) = EcKeyGen
            .ec_key_gen_pair(curve)
            .expect("Failed to generate EC keypair");
        (private_key, public_key)
    }

    #[test]
    // Checks that the derived key size is correct for all supported curves and platforms.
    fn test_ecdh_get_derived_key_size() {
        for &curve in CURVES.iter() {
            let (priv_key, _pub_key) = generate_keypair(curve);
            let size = priv_key.ecdh_get_derived_key_size();
            assert!(
                size.is_ok(),
                "ecdh_get_derived_key_size should succeed for {:?}",
                curve
            );
            let size = size.unwrap();
            // For P-256, should be 32 bytes; P-384: 48; P-521: 66 (Windows), 65 (Linux)
            //
            // P-521 is 521 bits, which is 65 bytes + 1 bit. Windows CNG always rounds up and returns 66 bytes for the shared secret.
            // OpenSSL (Linux) may return 65 bytes, as it sometimes strips leading zeroes or only returns the minimum number of bytes needed to represent the x-coordinate.
            // This is a platform difference: CNG is strict about returning ceil(521/8) = 66 bytes, while OpenSSL may return 65 bytes for P-521.
            // For interoperability, always use the value returned by ecdh_get_derived_key_size().
            let expected = match curve {
                EcCurveId::EccP256 => 32,
                EcCurveId::EccP384 => 48,
                EcCurveId::EccP521 => 66,
            };
            assert_eq!(
                size, expected,
                "Unexpected ECDH key size for {:?}: {}",
                curve, size
            );
        }
    }

    #[test]
    // Verifies that a shared secret can be derived for all supported curves and that the output length matches the expected size.
    fn test_ecdh_key_derive_success() {
        for &curve in CURVES.iter() {
            let (priv_key, pub_key) = generate_keypair(curve);
            let size = priv_key.ecdh_get_derived_key_size().unwrap();
            let mut secret = vec![0u8; size];
            let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
            assert!(
                result.is_ok(),
                "ecdh_key_derive should succeed for {:?}",
                curve
            );
            let shared = result.unwrap();
            assert_eq!(
                shared.len(),
                size,
                "Shared secret length should match derived key size for {:?}",
                curve
            );
        }
    }

    #[test]
    // Ensures that the function returns the correct error if the output buffer is too small.
    fn test_ecdh_key_derive_buffer_too_small() {
        for &curve in CURVES.iter() {
            let (priv_key, pub_key) = generate_keypair(curve);
            let size = priv_key.ecdh_get_derived_key_size().unwrap();
            let mut secret = vec![0u8; size - 1];
            let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
            assert!(
                matches!(result, Err(CryptoError::EcdhBufferTooSmall)),
                "Should return buffer too small error for {:?}",
                curve
            );
        }
    }

    #[test]
    // Test that attempting to derive a shared secret with keys from different curves fails as expected.
    fn test_ecdh_mismatched_curves() {
        // Generate keypairs for two different curves
        let (priv_key, _) = generate_keypair(EcCurveId::EccP256);
        let (_, pub_key) = generate_keypair(EcCurveId::EccP384);
        let size = priv_key.ecdh_get_derived_key_size().unwrap();
        let mut secret = vec![0u8; size];
        let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
        assert!(result.is_err(), "ECDH with mismatched curves should fail");
    }

    #[test]
    // Test that passing an invalid or corrupted public key returns an error.
    fn test_ecdh_invalid_public_key() {
        // Generate a valid keypair
        let (priv_key, mut pub_key) = generate_keypair(EcCurveId::EccP256);
        // Corrupt the public key by replacing its handle (simulate invalid key)
        // This is a hack: replace with a key from a different curve
        let (_, bad_pub_key) = generate_keypair(EcCurveId::EccP384);
        pub_key.public_key_handle = bad_pub_key.public_key_handle.clone();
        let size = priv_key.ecdh_get_derived_key_size().unwrap();
        let mut secret = vec![0u8; size];
        let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
        assert!(
            result.is_err(),
            "ECDH with invalid/corrupted public key should fail"
        );
    }

    #[test]
    // Test that passing a zero-length buffer returns EcdhBufferTooSmall.
    fn test_ecdh_zero_length_buffer() {
        let (priv_key, pub_key) = generate_keypair(EcCurveId::EccP256);
        let mut secret = vec![];
        let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
        assert!(
            matches!(result, Err(CryptoError::EcdhBufferTooSmall)),
            "Zero-length buffer should return EcdhBufferTooSmall"
        );
    }

    #[test]
    // Test that passing a buffer larger than required does not cause issues and the returned slice is the correct length.
    fn test_ecdh_oversized_buffer() {
        for &curve in CURVES.iter() {
            let (priv_key, pub_key) = generate_keypair(curve);
            let size = priv_key.ecdh_get_derived_key_size().unwrap();
            let mut secret = vec![0u8; size + 10]; // Oversized buffer
            let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
            assert!(
                result.is_ok(),
                "ECDH should succeed with oversized buffer for {:?}",
                curve
            );
            let shared = result.unwrap();
            // Always use the value returned by ecdh_get_derived_key_size()
            assert_eq!(
                shared.len(),
                size,
                "Returned slice should match derived key size for {:?}",
                curve
            );
        }
    }

    #[test]
    // Test concurrent calls to ecdh_key_derive to ensure locking works as expected (thread safety).
    fn test_ecdh_concurrent_derivation() {
        use std::sync::Arc;
        use std::thread;
        let (priv_key, pub_key) = generate_keypair(EcCurveId::EccP256);
        let priv_key = Arc::new(priv_key);
        let pub_key = Arc::new(pub_key);
        let size = priv_key.ecdh_get_derived_key_size().unwrap();
        let mut handles = vec![];
        for _ in 0..8 {
            let priv_key = Arc::clone(&priv_key);
            let pub_key = Arc::clone(&pub_key);
            handles.push(thread::spawn(move || {
                let mut secret = vec![0u8; size];
                let result = priv_key.ecdh_key_derive(&pub_key, &mut secret);
                assert!(result.is_ok(), "Concurrent ECDH should succeed");
                let shared = result.unwrap();
                assert_eq!(
                    shared.len(),
                    size,
                    "Shared secret length should match derived key size"
                );
            }));
        }
        for h in handles {
            h.join().expect("Thread panicked");
        }
    }
}
