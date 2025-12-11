// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! ECC module: provides types and traits for ECC key generation, signing, and verification of a digest.
//!
//! This module supports multiple platforms (Windows, Linux) and exposes a unified API for ECC operations.

#[cfg(target_os = "windows")]
mod ecc_cng;

#[cfg(target_os = "linux")]
mod ecc_ossl;

use crate::sha::HashAlgo;
use crate::CryptoError;

/// Trait for ECC signing operations
pub trait EccCryptSignOp {
    /// Signs the provided digest using the ECC private key.
    ///
    /// # Parameters
    /// - `digest`: The message digest to sign as a byte slice.
    /// - `signature`: Mutable byte slice to write the signature into.
    ///
    /// # Returns
    /// - `Ok(usize)`: The number of bytes written to the signature buffer on success.
    /// - `Err(CryptoError)`: An error if signing fails.
    fn ecc_crypt_sign<'a>(
        &self,
        digest: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;

    /// Returns the maximum size in bytes of a DER-encoded ECC signature for this key's curve and hash algorithm.
    ///
    /// This value is always at least as large as the largest possible DER-encoded signature for the curve,
    /// and never smaller than any actual signature that could be produced.
    ///
    /// # Arguments
    /// * `hash_algo` - Hash algorithm to check for support with the curve
    ///
    /// # Returns
    /// * `Ok(usize)` with the maximum DER signature size if supported
    /// * `Err(CryptoError::EccUnsupportedHashAlgorithm)` if the hash is not supported for the curve
    /// * `Err(CryptoError::EcCurveMismatch)` for unknown/unsupported curve
    fn ecc_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError>;
}

/// Trait for ECC signature verification operations
pub trait EccCryptVerifyOp {
    /// Verifies the provided signature against the digest using the ECC public key.
    ///
    /// # Parameters
    /// - `digest`: The message digest that was signed, as a byte slice.
    /// - `signature`: The signature to verify, as a byte slice.
    ///
    /// # Returns
    /// - `Ok(())`: If the signature is valid.
    /// - `Err(CryptoError)`: If the signature is invalid or verification fails.
    fn ecc_crypt_verify(&self, digest: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

#[cfg(test)]
mod tests {
    //! ECC sign/verify tests using only SHA digests (no internal hashing)

    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use test_log::test;

    use super::*;
    use crate::eckey::eckey_test_vectors::*;
    use crate::eckey::*;
    use crate::sha::HashAlgo;
    use crate::sha::HashOp;
    fn get_test_message() -> &'static [u8] {
        b"Test message for ECC signing"
    }

    /// Test ECC sign and verify for P-384 using SHA-384 digest.
    /// Ensures that a generated signature can be verified by the corresponding public key.
    #[test]
    fn test_ecc_sign_verify_p384() {
        let msg = get_test_message();
        let mut digest = [0u8; 48];
        HashAlgo::Sha384.hash(msg, &mut digest).unwrap();
        let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP384).unwrap();
        // Use ecc_crypt_get_signature_size to determine buffer size
        let sig_buf_len = priv_key
            .ecc_crypt_get_signature_size(HashAlgo::Sha384)
            .unwrap();
        let mut signature = vec![0u8; sig_buf_len];
        let signature = priv_key.ecc_crypt_sign(&digest, &mut signature).unwrap();
        assert!(pub_key.ecc_crypt_verify(&digest, signature).is_ok());
    }

    /// Test ECC sign and verify for P-521 using SHA-512 digest.
    /// Ensures that a generated signature can be verified by the corresponding public key.
    #[test]
    fn test_ecc_sign_verify_p521_sha512() {
        let msg = get_test_message();
        let mut digest = [0u8; 64];
        HashAlgo::Sha512.hash(msg, &mut digest).unwrap();
        let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP521).unwrap();
        // Use ecc_crypt_get_signature_size to determine buffer size
        let sig_buf_len = priv_key
            .ecc_crypt_get_signature_size(HashAlgo::Sha512)
            .unwrap();
        let mut signature = vec![0u8; sig_buf_len];
        let signature = priv_key.ecc_crypt_sign(&digest, &mut signature).unwrap();
        assert!(pub_key.ecc_crypt_verify(&digest, signature).is_ok());
    }

    /// Test that P-521 with SHA-256 (digest size 32) is not supported.
    /// Ensures that the implementation rejects invalid curve/hash combinations.
    #[test]
    fn test_ecc_sign_verify_p521_sha256() {
        // This combination is not supported: P-521 with SHA-256 (digest size 32)
        let msg = get_test_message();
        let mut digest = [0u8; 32];
        HashAlgo::Sha256.hash(msg, &mut digest).unwrap();
        let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP521).unwrap();
        let mut signature = vec![0u8; 144];
        let result = priv_key.ecc_crypt_sign(&digest, &mut signature);
        assert!(
            result.is_err(),
            "P-521 with SHA-256 should not be supported"
        );
    }

    /// Test ECC sign/verify for all valid (curve, hash) combinations.
    /// Ensures that only NIST-recommended and cross-platform supported pairs succeed.
    #[test]
    fn test_ecc_sign_verify_matrix() {
        use crate::sha::HashAlgo;
        let msg = get_test_message();
        // Only include valid (curve, hash) combinations per digest length rules
        let matrix = [
            (EcCurveId::EccP256, HashAlgo::Sha256, 32),
            (EcCurveId::EccP384, HashAlgo::Sha384, 48),
            (EcCurveId::EccP521, HashAlgo::Sha512, 64),
        ];
        for (curve, hash_algo, digest_len) in matrix.iter().cloned() {
            let mut digest = vec![0u8; digest_len];
            hash_algo.hash(msg, &mut digest).unwrap();
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            // Use ecc_crypt_get_signature_size to determine buffer size
            let sig_buf_len = priv_key.ecc_crypt_get_signature_size(hash_algo).unwrap();
            let mut signature = vec![0u8; sig_buf_len];
            let signature = priv_key.ecc_crypt_sign(&digest, &mut signature).unwrap();
            tracing::error!(
                "[ECC-MATRIX] Curve: {:?}, Hash: {:?}\n  Digest: {:02x?}\n  Signature (DER): {:02x?}",
                curve, hash_algo, digest, signature
            );
            let verify_result = pub_key.ecc_crypt_verify(&digest, signature);
            if let Err(e) = &verify_result {
                tracing::error!(
                    "[ECC-MATRIX] Verification failed!\n  Curve: {:?}\n  Hash: {:?}\n  Digest: {:02x?}\n  Signature: {:02x?}\n  Error: {:?}",
                    curve, hash_algo, digest, signature, e
                );
            }
            assert!(
                verify_result.is_ok(),
                "Failed for curve {:?} and hash {:?}",
                curve,
                hash_algo
            );
        }
    }

    /// Test minimum and maximum allowed digest lengths for each curve using real hash digests.
    /// Ensures that only valid digest lengths are accepted for each curve.
    #[test]
    fn test_ecc_digest_length_boundaries() {
        // Test minimum and maximum allowed digest lengths for each curve using real hash digests
        let msg = get_test_message();
        // Test only the NIST-recommended and universally supported curve/hash pairs
        let boundaries = [
            (EcCurveId::EccP256, 32, HashAlgo::Sha256),
            (EcCurveId::EccP384, 48, HashAlgo::Sha384),
            (EcCurveId::EccP521, 64, HashAlgo::Sha512),
        ];
        for (curve, digest_len, hash_algo) in boundaries.iter().cloned() {
            let mut digest = vec![0u8; digest_len];
            hash_algo.hash(msg, &mut digest).unwrap();
            let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let mut signature = vec![0u8; 144];
            let sig_slice = priv_key.ecc_crypt_sign(&digest, &mut signature).unwrap();
            assert!(
                pub_key.ecc_crypt_verify(&digest, sig_slice).is_ok(),
                "Boundary test failed for curve {:?} and digest_len {}",
                curve,
                digest_len
            );
        }
    }

    /// Test digest lengths that are not allowed (too short, too long, or not standard SHA sizes).
    /// Ensures that invalid digest lengths are rejected for each curve.
    #[test]
    fn test_ecc_invalid_digest_lengths() {
        // Test digest lengths that are not allowed (too short, too long, or not standard SHA sizes)
        let msg = get_test_message();
        let invalids = [
            (EcCurveId::EccP256, 64, Some(HashAlgo::Sha512)), // too long for P-256
            (EcCurveId::EccP384, 64, Some(HashAlgo::Sha512)), // too long for P-384
            (EcCurveId::EccP256, 17, None),                   // not a standard hash size
        ];
        for (curve, digest_len, hash_algo_opt) in invalids.iter().cloned() {
            let digest = if let Some(hash_algo) = hash_algo_opt {
                let mut d = vec![0u8; digest_len];
                // If the hash function doesn't match the length, fill with dummy data
                let _ = hash_algo.hash(msg, &mut d);
                d
            } else {
                vec![0xCD; digest_len]
            };
            let (priv_key, _pub_key) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let mut signature = vec![0u8; 144];
            let result = priv_key.ecc_crypt_sign(&digest, &mut signature);
            assert!(
                result.is_err(),
                "Expected error for curve {:?} and digest_len {}",
                curve,
                digest_len
            );
        }
    }

    /// Test signature verification with truncated or extended signature.
    /// Ensures that signature length mismatches are detected and rejected.
    #[test]
    fn test_ecc_invalid_signature_length() {
        // Test signature verification with truncated or extended signature
        let msg = get_test_message();
        let mut digest = [0u8; 32];
        HashAlgo::Sha256.hash(msg, &mut digest).unwrap();
        let (priv_key, pub_key) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP256).unwrap();
        let mut signature = vec![0u8; 72];
        let signature = priv_key.ecc_crypt_sign(&digest, &mut signature).unwrap();
        let sig_len = signature.len();
        // Truncate signature (invalid)
        let mut truncated = signature.to_vec();
        truncated.truncate(sig_len - 1);
        assert!(
            pub_key.ecc_crypt_verify(&digest, &truncated).is_err(),
            "Expected error for truncated signature"
        );
        // Extend signature (invalid)
        let mut extended = signature.to_vec();
        extended.push(0);
        assert!(
            pub_key.ecc_crypt_verify(&digest, &extended).is_err(),
            "Expected error for extended signature"
        );
    }

    /// Test ECC key import/export and round-trip DER encoding for both private and public keys.
    /// Ensures that keys can be imported from DER and exported back to DER, matching the original input.
    #[test]
    fn test_ecc_vector_key_import_export() {
        // Helper closures for repeated actions
        let import_priv = |der, curve, i| {
            EcPrivateKey::ec_key_from_der(der, curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import private key: {:?}", i, e))
        };
        let import_pub = |der, curve, i| {
            EcPublicKey::ec_key_from_der(der, curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import public key: {:?}", i, e))
        };
        let export_pub = |pub_key: &EcPublicKey, expected: &[u8], i| {
            let mut buf = vec![0u8; expected.len() + 16];
            let len = pub_key.ec_key_to_der(&mut buf).expect("DER export pub");
            buf.truncate(len);
            assert_eq!(buf, expected, "[{}] Public key DER round-trip failed", i);
        };
        #[cfg(target_os = "linux")]
        let export_priv_linux = |priv_key: &EcPrivateKey, expected: &[u8], i: usize| {
            let mut buf = vec![0u8; expected.len() + 16];
            let len = priv_key.ec_key_to_der(&mut buf).expect("DER export priv");
            buf.truncate(len);
            assert_eq!(buf, expected, "[{}] Private key DER round-trip failed", i);
        };
        let sign_and_verify = |priv_key: &EcPrivateKey, pub_key: &EcPublicKey, digest: &[u8], i| {
            let mut sig_buf = vec![0u8; 144];
            let sig_buf = priv_key.ecc_crypt_sign(digest, &mut sig_buf).expect("sign");
            if let Err(e) = pub_key.ecc_crypt_verify(digest, sig_buf) {
                tracing::error!(
                    "[{}] Sign/verify failed: {:?}\n  digest: {:02x?}\n  signature: {:02x?}",
                    i,
                    e,
                    digest,
                    sig_buf
                );
                panic!("[{}] Sign/verify failed", i);
            }
        };
        let verify_vector_sig = |pub_key: &EcPublicKey, digest: &[u8], sig: &[u8], i| {
            if let Err(e) = pub_key.ecc_crypt_verify(digest, sig) {
                tracing::error!("[{}] Vector signature verify failed (DER): {:?}\n  digest: {:02x?}\n  signature: {:02x?}", i, e, digest, sig);
                panic!("[{}] Vector signature verify failed (DER)", i);
            }
        };

        // Only allow NIST-recommended and cross-platform supported curve/hash pairs:
        // P-256/SHA-256, P-384/SHA-384, P-521/SHA-512
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!("[{}] running test vector for curve :{:?}", i, vector.curve);
            let priv_key = import_priv(vector.private_key_der, vector.curve, i);
            let pub_key = import_pub(vector.public_key_der, vector.curve, i);
            #[cfg(target_os = "linux")]
            export_priv_linux(&priv_key, vector.private_key_der, i);
            export_pub(&pub_key, vector.public_key_der, i);
            sign_and_verify(&priv_key, &pub_key, vector.digest, i);
            verify_vector_sig(&pub_key, vector.digest, vector.sig_der, i);
            assert!(priv_key.size().is_ok(), "[{}] priv_key.size() failed", i);
            assert!(pub_key.size().is_ok(), "[{}] pub_key.size() failed", i);
        }
    }

    /// Test that a signature generated for each test vector's key and digest is valid and can be verified.
    /// Does NOT compare signature bytes (ECC is non-deterministic); only checks signature validity.
    #[test]
    fn test_ecc_vector_sign_verify() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!("[{}] Testing sign/verify for curve {:?}", i, vector.curve);
            let priv_key = EcPrivateKey::ec_key_from_der(vector.private_key_der, vector.curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import private key: {:?}", i, e));
            let pub_key = EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import public key: {:?}", i, e));
            // Only check that the generated signature verifies, not that it matches the vector
            let mut sig_buf = vec![0u8; 144];
            let sig_buf = priv_key
                .ecc_crypt_sign(vector.digest, &mut sig_buf)
                .unwrap_or_else(|e| {
                    tracing::error!(
                        "[{}] Signing failed: {:?}\n  curve: {:?}\n  digest: {:02x?}\n  private_key_der: {:02x?}",
                        i, e, vector.curve, vector.digest, vector.private_key_der
                    );
                    panic!("[{}] Signing failed", i);
                });
            if let Err(e) = pub_key.ecc_crypt_verify(vector.digest, sig_buf) {
                tracing::error!(
                    "[{}] Sign/verify failed: {:?}\n  curve: {:?}\n  digest: {:02x?}\n  signature: {:02x?}\n  pub_key_der: {:02x?}",
                    i, e, vector.curve, vector.digest, sig_buf, vector.public_key_der
                );
                panic!("[{}] Sign/verify failed", i);
            }
        }
    }

    /// Test that the DER-encoded signature provided in each test vector is valid for the given public key and digest.
    /// Ensures that the test vector's signature is correct, but does NOT require our implementation to produce the same signature bytes.
    #[test]
    fn test_ecc_vector_verify_vector_signature() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            tracing::error!("[{}] Importing public key for curve {:?}", i, vector.curve);
            let pub_key = match EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve) {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("[{}] Failed to import public key: {:?}", i, e);
                    panic!("[{}] Failed to import public key: {:?}", i, e);
                }
            };
            tracing::error!(
                "[{}] Verifying vector signature: {:02x?}",
                i,
                vector.sig_der
            );
            let verify_result = pub_key.ecc_crypt_verify(vector.digest, vector.sig_der);
            if let Err(e) = &verify_result {
                tracing::error!("[{}] Vector signature verification failed: {:?}", i, e);
            }
            assert!(
                verify_result.is_ok(),
                "[{}] Vector signature verification failed",
                i
            );
        }
    }

    /// Stress test: sign and verify 100 times for each test vector to catch any sporadic or random issues.
    /// Ensures stability and robustness under repeated operations.
    #[test]
    fn test_ecc_vector_sign_verify_stress() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            println!(
                "[{}] Stress test sign/verify for curve {:?}",
                i, vector.curve
            );
            let priv_key = EcPrivateKey::ec_key_from_der(vector.private_key_der, vector.curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import private key: {:?}", i, e));
            let pub_key = EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import public key: {:?}", i, e));
            // Use ecc_crypt_get_signature_size for buffer allocation
            let sig_buf_len = priv_key
                .ecc_crypt_get_signature_size(vector.hash_algo)
                .unwrap_or(144); // fallback to 144 if not available (should not happen)
            for iter in 0..100 {
                let mut sig_buf = vec![0u8; sig_buf_len];
                // Only use the returned signature slice
                let sig_slice = priv_key
                    .ecc_crypt_sign(vector.digest, &mut sig_buf)
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            "[{}] Iter {}: Signing failed: {:?}\n  curve: {:?}\n  digest: {:02x?}\n  private_key_der: {:02x?}",
                            i, iter, e, vector.curve, vector.digest, vector.private_key_der
                        );
                        panic!("[{}] Iter {}: Signing failed", i, iter);
                    });

                if let Err(e) = pub_key.ecc_crypt_verify(vector.digest, sig_slice) {
                    tracing::error!(
                        "[{}] Iter {}: Sign/verify failed: {:?}\n  curve: {:?}\n  digest: {:02x?}\n  signature: {:02x?}\n  pub_key_der: {:02x?}",
                        i, iter, e, vector.curve, vector.digest, sig_slice, vector.public_key_der
                    );
                    panic!("[{}] Iter {}: Sign/verify failed", i, iter);
                }
            }
        }
    }

    /// Negative test: Try to import corrupted or tampered private/public keys and expect failure.
    #[test]
    fn test_ecc_import_corrupted_keys() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            // Corrupt a byte in the private key DER
            let mut corrupted_priv = vector.private_key_der.to_vec();
            let len = corrupted_priv.len();
            if len > 0 {
                corrupted_priv[len / 2] ^= 0xFF;
            }
            assert!(
                EcPrivateKey::ec_key_from_der(&corrupted_priv, vector.curve).is_err(),
                "[{}] Corrupted private key import should fail",
                i
            );
            // Corrupt a byte in the public key DER
            let mut corrupted_pub = vector.public_key_der.to_vec();
            let len = corrupted_pub.len();
            if len > 0 {
                corrupted_pub[len / 2] ^= 0xFF;
            }
            assert!(
                EcPublicKey::ec_key_from_der(&corrupted_pub, vector.curve).is_err(),
                "[{}] Corrupted public key import should fail",
                i
            );
        }
    }

    /// Negative test: Try to verify with tampered/corrupted signatures and expect failure.
    #[test]
    fn test_ecc_verify_tampered_signature() {
        for (i, vector) in NIST_EC_TEST_VECTORS.iter().enumerate() {
            let pub_key = EcPublicKey::ec_key_from_der(vector.public_key_der, vector.curve)
                .unwrap_or_else(|e| panic!("[{}] Failed to import public key: {:?}", i, e));
            // Corrupt a byte in the signature
            let mut tampered_sig = vector.sig_der.to_vec();
            let len = tampered_sig.len();
            if len > 0 {
                tampered_sig[len / 2] ^= 0xFF;
            }
            assert!(
                pub_key
                    .ecc_crypt_verify(vector.digest, &tampered_sig)
                    .is_err(),
                "[{}] Tampered signature should not verify",
                i
            );
        }
    }

    /// Fuzzing: Try to import random/malformed DER as private/public keys and expect failure.
    #[test]
    fn test_ecc_import_fuzzed_der() {
        let mut rng = StdRng::seed_from_u64(0xA5A5A5A5);
        for curve in [EcCurveId::EccP256, EcCurveId::EccP384, EcCurveId::EccP521] {
            for i in 0..50 {
                let mut fuzzed = vec![0u8; 64 + (rng.gen::<usize>() % 64)];
                rng.fill(&mut fuzzed[..]);
                assert!(
                    EcPrivateKey::ec_key_from_der(&fuzzed, curve).is_err(),
                    "Fuzzed private key DER should not import (curve {:?}, iter {})",
                    curve,
                    i
                );
                assert!(
                    EcPublicKey::ec_key_from_der(&fuzzed, curve).is_err(),
                    "Fuzzed public key DER should not import (curve {:?}, iter {})",
                    curve,
                    i
                );
            }
        }
    }

    /// Test ecc_crypt_get_signature_size for all valid (curve, hash) combinations and error cases.
    #[test]
    fn test_ecc_get_signature_size_matrix() {
        // Use the actual maximum DER signature sizes as returned by the implementation
        let matrix = [
            (EcCurveId::EccP256, HashAlgo::Sha256, 72), // as returned by impl
            (EcCurveId::EccP384, HashAlgo::Sha384, 107), // as returned by impl
            (EcCurveId::EccP521, HashAlgo::Sha512, 141), // as returned by impl
        ];
        for (curve, hash_algo, expected_size) in matrix.iter().cloned() {
            let (priv_key, _) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let size = priv_key.ecc_crypt_get_signature_size(hash_algo).unwrap();
            assert_eq!(
                size, expected_size,
                "Signature size mismatch for curve {:?} and hash {:?}",
                curve, hash_algo
            );
        }
    }

    /// Test ecc_crypt_get_signature_size returns error for unsupported hash algorithms and curves.
    #[test]
    fn test_ecc_get_signature_size_invalid() {
        // Unsupported hash for P-521 (should be Sha512 only)
        let (priv_key, _) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP521).unwrap();
        let err = priv_key
            .ecc_crypt_get_signature_size(HashAlgo::Sha256)
            .unwrap_err();
        assert_eq!(err, CryptoError::EccUnsupportedHashAlgorithm);

        // Unsupported curve (simulate by using an invalid degree if possible)
        // Not directly possible via public API, but we can check for a curve/hash mismatch
        let (priv_key, _) = EcKeyGen.ec_key_gen_pair(EcCurveId::EccP256).unwrap();
        let err = priv_key
            .ecc_crypt_get_signature_size(HashAlgo::Sha512)
            .unwrap_err();
        assert_eq!(err, CryptoError::EccUnsupportedHashAlgorithm);
    }
}
