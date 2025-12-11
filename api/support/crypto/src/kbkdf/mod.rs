// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! KBKDF (SP800-108) module for platform-specific key derivation.
//! Provides trait and struct definitions for key derivation operations.

mod kbkdf_common;

use crate::sha::HashAlgo;
use crate::CryptoError;

/// Trait for KBKDF key derivation operations.
///
/// Provides methods for key derivation using KBKDF (SP800-108).
pub trait KbkdfKeyDeriveOps {
    /// Derives a key using KBKDF (SP800-108).
    ///
    /// # Parameters
    /// - `hash_algo`: The hash algorithm to use (SHA256, SHA384, SHA512).
    /// - `label`: Optional label for KBKDF.
    /// - `context`: Optional context for KBKDF.
    /// - `out_len`: Desired output key length in bytes.
    /// - `secret_key`: Output buffer to receive the derived key.
    ///
    /// # Returns
    /// - `Ok(&[u8])`: Slice of the valid derived key bytes.
    /// - `Err(CryptoError)`: If any error occurs during key derivation.
    fn kbkdf_derive<'a>(
        &self,
        hash_algo: HashAlgo,
        label: Option<&[u8]>,
        context: Option<&[u8]>,
        out_len: usize,
        secret_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;
}

#[cfg(test)]
mod kbkdf_test_vectors;

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::ecdh::EcdhKeyDeriveOp;
    use crate::eckey::*;
    use crate::secretkey::*;
    use crate::sha::HashAlgo;

    /// Basic test for KBKDF key derivation (all supported SHA algorithms).
    #[test]
    fn test_kbkdf_derive_basic() {
        let base_key = [0x01u8; 64]; // Use max required for all algos
        let label = Some(&b"label"[..]);
        let context = Some(&b"context"[..]);
        let out_len = 32;
        let _key = SecretKey {
            kdk: base_key[..].to_vec(),
        };
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut out_buf = vec![0u8; out_len];
            let result = key.kbkdf_derive(*algo, label, context, out_len, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?}: {:?}",
                algo,
                result
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), out_len);
            assert!(derived.iter().any(|&b| b != 0));
        }
    }

    /// Test KBKDF key derivation for all supported SHA algorithms.
    #[test]
    fn test_kbkdf_derive_all_algos() {
        let base_key = [0x02u8; 64]; // Use max required for all algos
        let label = Some(&b"label"[..]);
        let context = Some(&b"context"[..]);
        let out_len = 32;
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut buf = vec![0u8; out_len];
            let result = key.kbkdf_derive(*algo, label, context, out_len, &mut buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?}: {:?}",
                algo,
                result
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), out_len);
            assert!(
                derived.iter().any(|&b| b != 0),
                "Output is all zeros for {:?}",
                algo
            );
        }
    }

    /// Basic test for KBKDF key derivation with all supported SHA algorithms.
    #[test]
    fn test_kbkdf_derive_basic_all_algos() {
        let base_key = [0x01u8; 64]; // Use max required for all algos
        let label = Some(&b"label"[..]);
        let context = Some(&b"context"[..]);
        let out_len = 32;
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut out_buf = vec![0u8; out_len];
            let result = key.kbkdf_derive(*algo, label, context, out_len, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?}: {:?}",
                algo,
                result
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), out_len);
            assert!(derived.iter().any(|&b| b != 0));
        }
    }

    /// Test that SecretKey::from_slice sets the key length correctly and can be used for derivation (all SHA algos).
    #[test]
    fn test_secretkey_from_slice_and_derive() {
        let base_key = [0xABu8; 64]; // Use max required for all algos
        let label = Some(&b"label"[..]);
        let context = Some(&b"context"[..]);
        let out_len = 32;
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key =
                SecretKey::from_slice(&base_key[..min_len]).expect("from_slice should succeed");
            assert_eq!(key.kdk.len(), min_len, "SecretKey.key length mismatch");
            let mut out_buf = vec![0u8; out_len];
            let result = key.kbkdf_derive(*algo, label, context, out_len, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?}: {:?}",
                algo,
                result
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), out_len);
            assert!(derived.iter().any(|&b| b != 0));
        }
    }

    /// Negative test: output length zero should fail.
    #[test]
    fn test_kbkdf_invalid_output_length() {
        let base_key = [0x01u8; 32];
        let key = SecretKey {
            kdk: base_key.to_vec(),
        };
        let mut out_buf = vec![];
        let result = key.kbkdf_derive(HashAlgo::Sha256, None, None, 0, &mut out_buf);
        assert!(result.is_err(), "Expected error for zero output length");
    }

    /// Negative test: SHA1 is not supported and should fail.
    #[test]
    fn test_kbkdf_unsupported_hash_algo() {
        let base_key = [0x01u8; 32];
        let key = SecretKey {
            kdk: base_key.to_vec(),
        };
        let mut out_buf = vec![0u8; 32];
        let result = key.kbkdf_derive(HashAlgo::Sha1, None, None, 32, &mut out_buf);
        assert!(
            result.is_err(),
            "Expected error for unsupported SHA1 hash algorithm"
        );
    }

    /// Corner case: very small output length (1 byte, all SHA algos)
    #[test]
    fn test_kbkdf_small_output() {
        let base_key = [0x01u8; 128];
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut out_buf = vec![0u8; 1];
            let result = key.kbkdf_derive(*algo, None, None, 1, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?} 1 byte output",
                algo
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), 1);
        }
    }

    /// Corner case: very large output length (e.g., 4096 bytes, all SHA algos)
    #[test]
    fn test_kbkdf_large_output() {
        let base_key = [0x01u8; 128];
        let out_len = 4096;
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let key = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut out_buf = vec![0u8; out_len];
            let result = key.kbkdf_derive(*algo, None, None, out_len, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?} large output",
                algo
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), out_len);
            assert!(derived.iter().any(|&b| b != 0));
        }
    }

    /// API usage: derive with empty label/context (all SHA algos)
    #[test]
    fn test_kbkdf_empty_label_context() {
        let base_key = [0x01u8; 128]; // Use max allowed for all algos
        let algos = [HashAlgo::Sha256, HashAlgo::Sha384, HashAlgo::Sha512];
        for algo in algos.iter() {
            let min_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).lower_bound;
            let max_len = crate::hmac::HmacKey::get_lower_upper_key_size(*algo).upper_bound;
            // Test with minimum allowed key size
            let key_min = SecretKey {
                kdk: base_key[..min_len].to_vec(),
            };
            let mut out_buf = vec![0u8; 32];
            let result = key_min.kbkdf_derive(*algo, Some(&[]), Some(&[]), 32, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?} empty label/context (min size)",
                algo
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), 32);
            assert!(derived.iter().any(|&b| b != 0));
            // Test with maximum allowed key size
            let key_max = SecretKey {
                kdk: base_key[..max_len].to_vec(),
            };
            let mut out_buf = vec![0u8; 32];
            let result = key_max.kbkdf_derive(*algo, Some(&[]), Some(&[]), 32, &mut out_buf);
            assert!(
                result.is_ok(),
                "KBKDF derive failed for {:?} empty label/context (max size)",
                algo
            );
            let derived = result.unwrap();
            assert_eq!(derived.len(), 32);
            assert!(derived.iter().any(|&b| b != 0));
        }
    }

    /// API usage: output buffer smaller than requested length
    #[test]
    fn test_kbkdf_output_buffer_too_small() {
        let base_key = [0x01u8; 32];
        let key = SecretKey {
            kdk: base_key.to_vec(),
        };
        let mut out_buf = vec![0u8; 8]; // less than out_len
        let result = key.kbkdf_derive(HashAlgo::Sha256, None, None, 32, &mut out_buf);
        assert!(
            result.is_err(),
            "Expected error for output buffer too small"
        );
    }

    /// Test with a NIST KBKDF vectors (CTRLOCATION = BEFORE_FIXED)
    #[test]
    fn test_nist_vectors() {
        for (index, vec) in kbkdf_test_vectors::KBKDF_CNT_BEFORE_TEST_VECTORS
            .iter()
            .enumerate()
        {
            println!("Vector :{}", index);
            let expected_ko = vec.ko;
            let key = SecretKey::from_slice(vec.ki).unwrap();
            let mut out_buf = vec![0u8; expected_ko.len()];
            let context = if vec.context.is_empty() {
                None
            } else {
                Some(vec.context)
            };
            let result = key.kbkdf_derive(
                vec.hash_algo,
                Some(vec.label),
                context,
                expected_ko.len(),
                &mut out_buf,
            );
            assert!(result.is_ok());
            let derived = result.unwrap();
            assert_eq!(derived, expected_ko);
        }
    }

    /// Test ECDH key agreement followed by KBKDF derivation.
    /// This simulates a realistic scenario where two parties use ECDH to establish
    /// a shared secret, then use KBKDF to derive application-specific keys.
    #[test]
    fn test_ecdh_to_kbkdf_integration() {
        // Test combinations where ECDH output size is compatible with KBKDF key requirements
        let test_cases = [
            (EcCurveId::EccP256, HashAlgo::Sha256), // 32 bytes ECDH, 32-64 bytes range for SHA256
            (EcCurveId::EccP384, HashAlgo::Sha256), // 48 bytes ECDH, 32-64 bytes range for SHA256
            (EcCurveId::EccP384, HashAlgo::Sha384), // 48 bytes ECDH, 48-128 bytes range for SHA384
            (EcCurveId::EccP521, HashAlgo::Sha384), // 66 bytes ECDH, 48-128 bytes range for SHA384
            (EcCurveId::EccP521, HashAlgo::Sha512), // 66 bytes ECDH, 64-128 bytes range for SHA512
        ];

        // Helper to generate a keypair for a given curve
        fn generate_keypair(curve: EcCurveId) -> (EcPrivateKey, EcPublicKey) {
            EcKeyGen
                .ec_key_gen_pair(curve)
                .expect("Failed to generate EC keypair")
        }

        for &(curve, hash_algo) in test_cases.iter() {
            // Generate two keypairs (local and peer)
            let (local_priv, local_pub) = generate_keypair(curve);
            let (peer_priv, peer_pub) = generate_keypair(curve);

            // Both parties perform ECDH to get the same shared secret
            let shared_secret_size = local_priv.ecdh_get_derived_key_size().unwrap();

            let mut local_shared_secret = vec![0u8; shared_secret_size];
            let local_result = local_priv.ecdh_key_derive(&peer_pub, &mut local_shared_secret);
            assert!(
                local_result.is_ok(),
                "Local ECDH failed for {:?}: {:?}",
                curve,
                local_result
            );
            let local_shared = local_result.unwrap();

            let mut peer_shared_secret = vec![0u8; shared_secret_size];
            let peer_result = peer_priv.ecdh_key_derive(&local_pub, &mut peer_shared_secret);
            assert!(
                peer_result.is_ok(),
                "Peer ECDH failed for {:?}: {:?}",
                curve,
                peer_result
            );
            let peer_shared = peer_result.unwrap();

            // Verify both parties have the same shared secret
            assert_eq!(
                local_shared, peer_shared,
                "Shared secrets don't match for {:?}",
                curve
            );

            // Use the shared secret as input to KBKDF
            let kbkdf_key = SecretKey::from_slice(local_shared).unwrap();

            // Test various KBKDF scenarios
            let label = Some(&b"test-label"[..]);
            let context = Some(&b"test-context"[..]);
            let output_len = 32;

            let mut derived_key = vec![0u8; output_len];
            let kbkdf_result =
                kbkdf_key.kbkdf_derive(hash_algo, label, context, output_len, &mut derived_key);

            assert!(
                kbkdf_result.is_ok(),
                "KBKDF derivation failed for {:?} + {:?}: {:?}",
                curve,
                hash_algo,
                kbkdf_result
            );

            let derived = kbkdf_result.unwrap();
            assert_eq!(derived.len(), output_len);
            assert!(
                derived.iter().any(|&b| b != 0),
                "Derived key is all zeros for {:?} + {:?}",
                curve,
                hash_algo
            );

            // Verify deterministic behavior - same inputs should produce same output
            let mut derived_key2 = vec![0u8; output_len];
            let kbkdf_result2 =
                kbkdf_key.kbkdf_derive(hash_algo, label, context, output_len, &mut derived_key2);
            assert!(kbkdf_result2.is_ok());
            assert_eq!(
                derived,
                kbkdf_result2.unwrap(),
                "KBKDF should be deterministic for {:?} + {:?}",
                curve,
                hash_algo
            );
        }
    }

    /// Test that ECDH output is suitable for KBKDF with various output sizes.
    /// Tests the full range of practical key derivation scenarios.
    #[test]
    fn test_ecdh_kbkdf_various_output_sizes() {
        use crate::ecdh::EcdhKeyDeriveOp;
        use crate::eckey::*;

        let curve = EcCurveId::EccP256; // Use P-256 for efficiency
        let hash_algo = HashAlgo::Sha256;

        // Generate keypair and derive shared secret
        let (local_priv, local_pub) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
        let (_peer_priv, _) = EcKeyGen.ec_key_gen_pair(curve).unwrap();

        let shared_secret_size = local_priv.ecdh_get_derived_key_size().unwrap();
        let mut shared_secret = vec![0u8; shared_secret_size];
        let result = local_priv.ecdh_key_derive(&local_pub, &mut shared_secret);
        assert!(result.is_ok());
        let shared = result.unwrap();

        let kbkdf_key = SecretKey::from_slice(shared).unwrap();

        // Test various output sizes common in cryptographic applications
        let output_sizes = [16, 24, 32, 48, 64, 128, 256];

        for &output_size in output_sizes.iter() {
            let mut derived_key = vec![0u8; output_size];
            let result = kbkdf_key.kbkdf_derive(
                hash_algo,
                Some(&b"app-key"[..]),
                Some(&b"session-001"[..]),
                output_size,
                &mut derived_key,
            );

            assert!(
                result.is_ok(),
                "KBKDF failed for output size {}: {:?}",
                output_size,
                result
            );

            let derived = result.unwrap();
            assert_eq!(derived.len(), output_size);
            assert!(
                derived.iter().any(|&b| b != 0),
                "Derived key is all zeros for output size {}",
                output_size
            );
        }
    }

    /// Test ECDH-KBKDF with different label/context combinations.
    /// Ensures robust handling of different parameter combinations.
    #[test]
    fn test_ecdh_kbkdf_label_context_variations() {
        use crate::ecdh::EcdhKeyDeriveOp;
        use crate::eckey::*;

        let curve = EcCurveId::EccP384; // Test with P-384
        let hash_algo = HashAlgo::Sha384;

        // Generate shared secret
        let (local_priv, local_pub) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
        let (_peer_priv, _) = EcKeyGen.ec_key_gen_pair(curve).unwrap();

        let shared_secret_size = local_priv.ecdh_get_derived_key_size().unwrap();
        let mut shared_secret = vec![0u8; shared_secret_size];
        let result = local_priv.ecdh_key_derive(&local_pub, &mut shared_secret);
        assert!(result.is_ok());
        let shared = result.unwrap();

        let kbkdf_key = SecretKey::from_slice(shared).unwrap();

        // Test various label/context combinations (avoiding empty strings vs None since they behave identically)
        let test_cases = [
            (None, None),
            (Some(&b"label"[..]), None),
            (None, Some(&b"context"[..])),
            (Some(&b"app-label"[..]), Some(&b"session-context"[..])),
            (
                Some(&b"different-label"[..]),
                Some(&b"different-context"[..]),
            ),
            (
                Some(&b"long-application-specific-label"[..]),
                Some(&b"detailed-session-context-info"[..]),
            ),
        ];

        let output_len = 32;
        let mut previous_outputs = Vec::new();

        for (i, &(label, context)) in test_cases.iter().enumerate() {
            let mut derived_key = vec![0u8; output_len];
            let result =
                kbkdf_key.kbkdf_derive(hash_algo, label, context, output_len, &mut derived_key);

            assert!(
                result.is_ok(),
                "KBKDF failed for test case {}: {:?}",
                i,
                result
            );

            let derived = result.unwrap();
            assert_eq!(derived.len(), output_len);
            assert!(
                derived.iter().any(|&b| b != 0),
                "Derived key is all zeros for test case {}",
                i
            );

            // Ensure different inputs produce different outputs
            for (j, prev_output) in previous_outputs.iter().enumerate() {
                assert_ne!(
                    derived, *prev_output,
                    "Test case {} and {} produced identical outputs",
                    i, j
                );
            }

            previous_outputs.push(derived.to_vec());
        }
    }

    /// Test that different ECDH shared secrets produce different KBKDF outputs.
    /// Ensures proper entropy propagation from ECDH to KBKDF.
    #[test]
    fn test_ecdh_kbkdf_different_secrets_different_outputs() {
        use crate::ecdh::EcdhKeyDeriveOp;
        use crate::eckey::*;

        let curve = EcCurveId::EccP256; // Use P-256 for efficiency in CI
        let hash_algo = HashAlgo::Sha256;

        let mut derived_keys = Vec::new();

        // Generate multiple ECDH operations with different key pairs
        for i in 0..3 {
            let (local_priv, local_pub) = EcKeyGen.ec_key_gen_pair(curve).unwrap();
            let (peer_priv, peer_pub) = EcKeyGen.ec_key_gen_pair(curve).unwrap();

            // Use different key combinations
            let (priv_key, pub_key) = if i % 2 == 0 {
                (&local_priv, &peer_pub)
            } else {
                (&peer_priv, &local_pub)
            };

            let shared_secret_size = priv_key.ecdh_get_derived_key_size().unwrap();
            let mut shared_secret = vec![0u8; shared_secret_size];
            let result = priv_key.ecdh_key_derive(pub_key, &mut shared_secret);
            assert!(result.is_ok());
            let shared = result.unwrap();

            let kbkdf_key = SecretKey::from_slice(shared).unwrap();

            let mut derived_key = vec![0u8; 32];
            let result = kbkdf_key.kbkdf_derive(
                hash_algo,
                Some(&b"constant-label"[..]),
                Some(&b"constant-context"[..]),
                32,
                &mut derived_key,
            );

            assert!(result.is_ok());
            let derived = result.unwrap();

            // Ensure this output is different from all previous outputs
            for (j, prev_key) in derived_keys.iter().enumerate() {
                assert_ne!(
                    derived, *prev_key,
                    "ECDH operation {} and {} produced identical KBKDF outputs",
                    i, j
                );
            }

            derived_keys.push(derived.to_vec());
        }
    }
}
