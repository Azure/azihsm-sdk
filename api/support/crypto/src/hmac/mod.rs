// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! This crate provides HMAC (Hash-based Message Authentication Code) functionality,
//! including both single-shot and streaming APIs for cryptographic operations.

#[cfg(target_os = "windows")]
mod hmac_cng;

#[cfg(target_os = "linux")]
mod hmac_ossl;

mod hmac_key;

use crate::CryptoError;
use crate::HashAlgo;

/// Trait for HMAC signing operations.
///
/// Provides one-shot and streaming HMAC signing APIs.
pub trait HmacCryptSignOp {
    /// Performs a one-shot HMAC sign operation.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    /// * `data` - The data to sign.
    /// * `signature` - The output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(&[u8])` with the signature on success.
    /// * `Err(CryptoError)` if signing fails.
    fn hmac_crypt_sign<'a>(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;

    /// Initializes a streaming signing context for multi-part signing.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(HmacCryptSignContextOp)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    fn hmac_crypt_sign_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptSignContextOp, CryptoError>;

    /// Returns the required signature buffer size for the given hash algorithm.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(usize)` with the required buffer size.
    fn hmac_crypt_get_signature_size(&self, hash_algo: HashAlgo) -> Result<usize, CryptoError>;
}
/// Trait for streaming (multi-part) HMAC signing context.
///
/// Provides update and finalize methods for streaming HMAC signing.
pub trait HmacCryptSignContextOp {
    /// Updates the signing context with more data.
    ///
    /// # Arguments
    /// * `data` - The data to add to the HMAC.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails or if data is empty.
    ///
    /// # Note
    /// Empty data is not allowed for streaming HMAC updates. This is to prevent accidental no-op updates and to catch logic errors early.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
    /// Finalizes the signature and writes it to the output buffer.
    ///
    /// # Arguments
    /// * `signature` - The output buffer for the signature.
    ///
    /// # Returns
    /// * `Ok(&[u8])` with the signature on success.
    /// * `Err(CryptoError)` if finalization fails or the buffer is too small.
    fn finalize(self, signature: &mut [u8]) -> Result<&[u8], CryptoError>;
}

/// Trait for HMAC signature verification (one-shot and streaming).
///
/// Provides one-shot and streaming HMAC verification APIs.
pub trait HmacCryptVerifyOp {
    /// Performs a one-shot HMAC verify operation.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    /// * `data` - The data to verify.
    /// * `signature` - The signature to check against.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails or the signature is invalid.
    fn hmac_crypt_verify(
        &self,
        hash_algo: HashAlgo,
        data: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Initializes a streaming verification context for multi-part verification.
    ///
    /// # Arguments
    /// * `self` - The HMAC key object containing key material.
    /// * `hash_algo` - The hash algorithm to use.
    ///
    /// # Returns
    /// * `Ok(HmacCryptVerifyContextOp)` with the initialized context on success.
    /// * `Err(CryptoError)` if initialization fails.
    fn hmac_crypt_verify_init(
        &self,
        hash_algo: HashAlgo,
    ) -> Result<impl HmacCryptVerifyContextOp, CryptoError>;
}

/// Represents an HMAC key.
///
/// This struct encapsulates the key material used for HMAC operations.
pub struct HmacKey {
    key: Vec<u8>,
}

/// Trait for HMAC key operations.
pub trait HmacKeyOp {
    /// Creates an HmacKey from a slice of bytes.
    ///
    /// # Arguments
    /// * `key` - The key material as a byte slice.
    ///
    /// # Returns
    /// * `Ok(HmacKey)` if the key is valid and created successfully.
    /// * `Err(CryptoError)` if the key is invalid or creation fails.
    fn from_slice(key: &[u8]) -> Result<HmacKey, CryptoError>;
}

/// Trait for streaming (multi-part) HMAC verification context.
///
/// Provides update and finalize methods for streaming HMAC verification.
pub trait HmacCryptVerifyContextOp {
    /// Updates the verification context with more data.
    ///
    /// # Arguments
    /// * `data` - The data to add to the HMAC verification.
    ///
    /// # Returns
    /// * `Ok(())` on success.
    /// * `Err(CryptoError)` if the update fails or if data is empty.
    ///
    /// # Note
    /// Empty data is not allowed for streaming HMAC updates. This is to prevent accidental no-op updates and to catch logic errors early.
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError>;
    /// Finalizes the verification and checks the signature.
    ///
    /// # Arguments
    /// * `signature` - The signature to check against.
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid.
    /// * `Err(CryptoError)` if verification fails or the signature is invalid.
    fn finalize(self, signature: &[u8]) -> Result<(), CryptoError>;
}

#[cfg(test)]
mod hmac_test_vectors;

#[cfg(test)]
mod tests {
    use rand::Rng;
    use test_log::test;

    use super::*;
    use crate::sha::HashAlgo;

    // Common array of all supported hash algorithms for HMAC tests
    const ALL_HMAC_HASHALGOS: [HashAlgo; 4] = [
        HashAlgo::Sha1,
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
    ];

    fn get_test_key_bytes_for_algo(algo: HashAlgo) -> Vec<u8> {
        let range = HmacKey::get_lower_upper_key_size(algo);
        // Use a key at the lower bound for each algorithm
        vec![0xAB; range.lower_bound]
    }
    fn get_test_key_for_algo(algo: HashAlgo) -> HmacKey {
        HmacKey::from_slice(&get_test_key_bytes_for_algo(algo)).unwrap()
    }

    fn get_test_data() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog".to_vec()
    }

    // Test: HMAC sign and verify for all supported algorithms
    // Intention: Ensure that the implementation can sign and verify using all supported hash algorithms (SHA-1, SHA-256, SHA-384, SHA-512) with a valid key and data.
    // Expected result: Signature is produced and verified successfully for each algorithm.
    #[test]
    fn test_hmac_sign_and_verify_all_algos() {
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let out = key
                .hmac_crypt_sign(algo, &data, sig.as_mut_slice())
                .unwrap();
            key.hmac_crypt_verify(algo, &data, out).unwrap();
        }
    }

    // Test: HMAC sign with buffer too small
    // Intention: Ensure that the implementation returns an error if the output buffer is too small for the signature.
    // Expected result: Returns CryptoError::HmacSignatureBufferTooSmall.
    #[test]
    fn test_hmac_sign_buffer_too_small() {
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut sig = vec![0u8; 8]; // too small
            let err = key.hmac_crypt_sign(algo, &data, &mut sig).unwrap_err();
            assert_eq!(err, CryptoError::HmacSignatureBufferTooSmall);
        }
    }

    // Test: HMAC verify with tampered signature
    // Intention: Ensure that signature verification fails if the signature is tampered.
    // Expected result: Returns CryptoError::HmacSignatureMismatch.
    #[test]
    fn test_hmac_sign_and_verify_negative() {
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let out = key.hmac_crypt_sign(algo, &data, &mut sig).unwrap();
            // Tamper signature
            let mut tampered = out.to_vec();
            tampered[0] ^= 0xFF;
            let err = key.hmac_crypt_verify(algo, &data, &tampered).unwrap_err();
            assert_eq!(err, CryptoError::HmacSignatureMismatch);
        }
    }

    // Test: HMAC sign and verify with empty data
    // Intention: Ensure that signing and verifying an empty message works for all supported algorithms.
    // Expected result: Signature is produced and verified successfully for each algorithm with empty data.
    #[test]
    fn test_hmac_sign_and_verify_empty_data() {
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let data = vec![];
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let out = key.hmac_crypt_sign(algo, &data, &mut sig).unwrap();
            key.hmac_crypt_verify(algo, &data, out).unwrap();
        }
    }

    // Test: HMAC sign and verify with large data
    // Intention: Ensure that the implementation can handle large input data (1MB) for signing and verification.
    // Expected result: Signature is produced and verified successfully for large data.
    #[test]
    fn test_hmac_sign_and_verify_large_data() {
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut data = vec![0u8; 1024 * 1024];
            rand::thread_rng().fill(&mut data[..]);
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let out = key.hmac_crypt_sign(algo, &data, &mut sig).unwrap();
            key.hmac_crypt_verify(algo, &data, out).unwrap();
        }
    }

    // Test: Streaming HMAC sign and verify
    // Intention: Ensure that the streaming (multi-part) API produces the same result as the one-shot API for signing and verification.
    // Expected result: Streaming signature matches one-shot signature and verifies successfully.
    #[test]
    fn test_hmac_streaming_sign_and_verify() {
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut ctx = key.hmac_crypt_sign_init(algo).unwrap();
            for chunk in data.chunks(8) {
                ctx.update(chunk).unwrap();
            }
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let out = ctx.finalize(&mut sig).unwrap();
            let mut vctx = key.hmac_crypt_verify_init(algo).unwrap();
            for chunk in data.chunks(8) {
                vctx.update(chunk).unwrap();
            }
            vctx.finalize(out).unwrap();
        }
    }

    // Test: Streaming HMAC sign update with empty data
    // Intention: Ensure that updating the streaming context with empty data returns an error.
    // Expected result: Returns CryptoError::HmacSignFail.
    #[test]
    fn test_hmac_streaming_update_empty() {
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut ctx = key.hmac_crypt_sign_init(algo).unwrap();
            let err = ctx.update(&[]).unwrap_err();
            assert_eq!(err, CryptoError::HmacSignFail);
        }
    }

    // Test: Streaming HMAC verify update with empty data
    // Intention: Ensure that updating the streaming verification context with empty data returns an error.
    // Expected result: Returns CryptoError::HmacVerifyFail.
    #[test]
    fn test_hmac_streaming_verify_update_empty() {
        for algo in ALL_HMAC_HASHALGOS {
            let key = get_test_key_for_algo(algo);
            let mut vctx = key.hmac_crypt_verify_init(algo).unwrap();
            let err = vctx.update(&[]).unwrap_err();
            assert_eq!(err, CryptoError::HmacVerifyFail);
        }
    }

    // Test: HMAC sign with zero-length key
    // Intention: Ensure that the implementation rejects zero-length keys for all supported algorithms.
    // Expected result: Returns error for all algorithms when key is empty.
    #[test]
    fn test_hmac_zero_length_key() {
        // Test with a zero-length key for all supported algorithms
        let key_bytes: [u8; 0] = [];
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = HmacKey {
                key: key_bytes.to_vec(),
            };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            // Should fail (empty key is not allowed by implementation)
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_err(),
                "Empty key should be rejected for {:?}",
                algo
            );
        }
    }

    // Test: HMAC sign with very large key
    // Intention: Ensure that the implementation rejects keys above the allowed upper bound for all supported algorithms.
    // Expected result: Returns error for all algorithms when key is too large.
    #[test]
    fn test_hmac_very_large_key() {
        // Test with a very large key (e.g., 4096 bytes) for all supported algorithms
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let range = HmacKey::get_lower_upper_key_size(algo);
            let key = HmacKey {
                key: vec![0xCD; range.upper_bound + 100],
            };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            // Should fail (key is above upper bound)
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_err(),
                "Key size above upper bound should be rejected for {:?}",
                algo
            );
        }
    }

    // Test: HMAC backend failure simulation
    // Intention: Simulate backend failure (e.g., invalid algorithm or empty key) and ensure error is returned.
    // Expected result: Returns error for invalid algorithm or empty key.
    #[test]
    fn test_hmac_backend_failure() {
        // Simulate a backend failure by using an invalid algorithm (if possible)
        let data = get_test_data();
        // Use an invalid enum value if possible (here, we use a custom invalid value)
        // This requires HashAlgo to be extensible or use unsafe, so we just check for a known good value and skip otherwise
        // This is a placeholder for platform-specific backend failure simulation
        // let invalid_algo = unsafe { std::mem::transmute(0xFFu8) };
        // let result = key.hmac_crypt_sign(&key_bytes, invalid_algo, &data, &mut [0u8; 32]);
        // assert!(result.is_err());
        // Instead, test with a valid algo but empty key (should fail for all algorithms)
        for algo in ALL_HMAC_HASHALGOS {
            let key = HmacKey { key: vec![] };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_err(),
                "Empty key should be rejected for {:?}",
                algo
            );
        }
    }

    // Test: Concurrent HMAC sign and verify
    // Intention: Ensure that the implementation is thread-safe and can handle concurrent sign/verify operations.
    // Expected result: All concurrent operations succeed without panics or data races.
    #[test]
    fn test_hmac_concurrent_sign_verify() {
        // Test concurrent sign/verify operations (thread safety) for all supported algorithms
        use std::sync::Arc;
        use std::thread;
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let key = Arc::new(get_test_key_for_algo(algo));
            let mut handles = vec![];
            for _ in 0..8 {
                let key = Arc::clone(&key);
                let data = data.clone();
                handles.push(thread::spawn(move || {
                    let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
                    let out = key.hmac_crypt_sign(algo, &data, &mut sig).unwrap();
                    key.hmac_crypt_verify(algo, &data, out).unwrap();
                }));
            }
            for h in handles {
                h.join().unwrap();
            }
        }
    }

    // Test: HMAC key size range enforcement
    // Intention: Ensure that keys below the lower bound and above the upper bound are rejected, and keys at the bounds are accepted for all algorithms.
    // Expected result: Error for too small/large keys, success for keys at bounds.
    #[test]
    fn test_hmac_key_size_range() {
        // Test with keys that are too small, too large, and within range for all supported algorithms
        let data = get_test_data();
        for algo in ALL_HMAC_HASHALGOS {
            let range = HmacKey::get_lower_upper_key_size(algo);
            // Too small
            if range.lower_bound > 0 {
                let key = HmacKey {
                    key: vec![0xAA; range.lower_bound - 1],
                };
                let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
                let result = key.hmac_crypt_sign(algo, &data, &mut sig);
                assert!(
                    result.is_err(),
                    "Key size below lower bound should be rejected for {:?}",
                    algo
                );
            }
            // Too large
            let key = HmacKey {
                key: vec![0xBB; range.upper_bound + 1],
            };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_err(),
                "Key size above upper bound should be rejected for {:?}",
                algo
            );
            // In range (lower bound)
            let key = HmacKey {
                key: vec![0xCC; range.lower_bound],
            };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_ok(),
                "Key size at lower bound should be accepted for {:?}",
                algo
            );
            // In range (upper bound)
            let key = HmacKey {
                key: vec![0xCC; range.upper_bound],
            };
            let mut sig = vec![0u8; key.hmac_crypt_get_signature_size(algo).unwrap()];
            let result = key.hmac_crypt_sign(algo, &data, &mut sig);
            assert!(
                result.is_ok(),
                "Key size at upper bound should be accepted for {:?}",
                algo
            );
        }
    }

    // Test: NIST HMAC test vectors
    // Intention: Validate the implementation against official NIST HMAC test vectors for all supported algorithms, including handling of truncated MACs (Tlen).
    // Expected result: All vectors pass unless the key is out of range; truncated MACs are compared correctly.
    #[test]
    fn test_nist_hmac_vectors() {
        use hmac_test_vectors::HMAC_TEST_VECTORS;
        for (i, vector) in HMAC_TEST_VECTORS.iter().enumerate() {
            let key = match HmacKey::from_slice(vector.key) {
                Ok(key) => key,
                Err(e) => {
                    // Check if we got either HmacKeyTooShort or HmacKeyTooLong
                    if e == CryptoError::HmacKeyTooShort || e == CryptoError::HmacKeyTooLong {
                        tracing::warn!("Vector[#{i}] with unsupported key size : {:?}", e);
                    } else {
                        panic!("[NIST HMAC vector #{i}] HMAC sign failed for {:?}", e);
                    }
                    continue;
                }
            };
            let algo = vector.hash_algo;
            let msg = vector.msg;
            let expected_mac = vector.mac;
            let range = HmacKey::get_lower_upper_key_size(algo);
            let full_mac_len = key.hmac_crypt_get_signature_size(algo).unwrap();
            let mut mac = vec![0u8; full_mac_len];
            if key.key.len() < range.lower_bound || key.key.len() > range.upper_bound {
                // Key is out of allowed range, expect failure
                let result = key.hmac_crypt_sign(algo, msg, &mut mac);
                assert!(result.is_err(), "[NIST HMAC vector #{i}] Expected failure for key size {} (bounds: {}-{}) for {:?}", key.key.len(), range.lower_bound, range.upper_bound, algo);
            } else {
                // Key is in allowed range, expect success and correct MAC
                let result = key.hmac_crypt_sign(algo, msg, &mut mac);
                // NIST test vectors may specify a truncated MAC (Tlen < full output size).
                // Only compare the first expected_mac.len() bytes of the computed MAC to the expected value.
                if result.is_err() || {
                    let mac_out = result.as_ref().unwrap();
                    &mac_out[..expected_mac.len()] != expected_mac
                } {
                    tracing::error!("\n[NIST HMAC vector #{}]", i);
                    tracing::error!("  Algo: {:?}", algo);
                    tracing::error!("  Key: {:02X?}", &key.key);
                    tracing::error!("  Msg: {:02X?}", msg);
                    tracing::error!("  Expected MAC: {:02X?}", expected_mac);
                    if let Ok(mac_out) = &result {
                        tracing::error!("  Computed MAC: {:02X?}", &mac_out[..expected_mac.len()]);
                    } else {
                        tracing::error!("  HMAC sign failed");
                    }
                }
                assert!(
                    result.is_ok(),
                    "[NIST HMAC vector #{i}] HMAC sign failed for {:?}",
                    algo
                );
                let mac_out = result.unwrap();
                assert!(mac_out.len() >= expected_mac.len(), "[NIST HMAC vector #{i}] Returned MAC too short for {:?}: got {}, expected at least {}", algo, mac_out.len(), expected_mac.len());
                assert_eq!(
                    &mac_out[..expected_mac.len()],
                    expected_mac,
                    "[NIST HMAC vector #{i}] HMAC mismatch for {:?}",
                    algo
                );
            }
        }
    }
}
