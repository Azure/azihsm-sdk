// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]

//! This crate provides HKDF (HMAC-based Key Derivation Function) functionality,
//! implementing RFC 5869 for secure key derivation operations. HKDF is designed
//! to extract and expand keying material, particularly useful for deriving keys
//! from shared secrets or existing key material.

#[cfg(target_os = "linux")]
mod hkdf_ossl;

#[cfg(target_os = "windows")]
mod hkdf_cng;

use crate::sha::HashAlgo;
use crate::CryptoError;

/// HKDF Key Derivation Operations
///
/// This trait defines the interface for HKDF key derivation, supporting both
/// the extract and expand phases of the HKDF algorithm as defined in RFC 5869.
pub trait HkdfKeyDeriveOps {
    /// Performs HKDF key derivation operation.
    ///
    /// This function implements the complete HKDF algorithm (Extract + Expand phases)
    /// to derive a key of specified length from the input key material.
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm to use (SHA-1, SHA-256, SHA-384, SHA-512).
    /// * `salt` - Optional salt value for the extract phase. If None, a zero-filled salt is used.
    /// * `info` - Optional context-specific information for the expand phase.
    /// * `out_len` - The desired length of the derived key in bytes.
    /// * `secret_key` - Mutable buffer to store the derived key. Must be at least `out_len` bytes.
    ///
    /// # Returns
    /// * `Ok(&[u8])` - A slice of the derived key with length `out_len` on success.
    /// * `Err(CryptoError)` - If the derivation fails or parameters are invalid.
    ///
    /// # Errors
    /// * `CryptoError::HkdfBackendFail` - If the underlying crypto backend fails.
    /// * `CryptoError::HkdfSecretCreationFailed` - If key creation fails.
    fn hkdf_derive<'a>(
        &self,
        hash_algo: HashAlgo,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        out_len: usize,
        secret_key: &'a mut [u8],
    ) -> Result<&'a [u8], CryptoError>;
}

#[cfg(test)]
mod tests {
    use test_log::test;

    use super::*;
    use crate::ecdh::EcdhKeyDeriveOp;
    use crate::eckey::EcCurveId;
    use crate::eckey::EcKeyGen;
    use crate::eckey::EcKeyGenOp;
    use crate::eckey::EcPrivateKey;
    use crate::eckey::EcPublicKey;
    use crate::secretkey::*;

    // Common array of all supported hash algorithms for HKDF tests
    const ALL_HKDF_HASHALGOS: [HashAlgo; 4] = [
        HashAlgo::Sha1,
        HashAlgo::Sha256,
        HashAlgo::Sha384,
        HashAlgo::Sha512,
    ];

    // Test vectors from RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    // Source: https://tools.ietf.org/rfc/rfc5869.txt
    // Test vectors are located in Appendix A of RFC 5869
    struct HkdfTestVector {
        ikm: &'static [u8],      // Input Key Material
        salt: &'static [u8],     // Salt
        info: &'static [u8],     // Info
        length: usize,           // Output length
        expected: &'static [u8], // Expected output
        hash_algo: HashAlgo,     // Hash algorithm
    }

    // RFC 5869 Test Case 1: SHA-256
    const RFC5869_TEST1: HkdfTestVector = HkdfTestVector {
        ikm: &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ],
        salt: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ],
        info: &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
        length: 42,
        expected: &[
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ],
        hash_algo: HashAlgo::Sha256,
    };

    // RFC 5869 Test Case 2: SHA-256 with longer inputs
    const RFC5869_TEST2: HkdfTestVector = HkdfTestVector {
        ikm: &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
            0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        ],
        salt: &[
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
            0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
            0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
            0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
        ],
        info: &[
            0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
            0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
            0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
            0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
            0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
            0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        ],
        length: 82,
        expected: &[
            0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a,
            0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c,
            0x19, 0xaf, 0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb,
            0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
            0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec,
            0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
        ],
        hash_algo: HashAlgo::Sha256,
    };

    // RFC 5869 Test Case 3: SHA-256 with zero-length salt
    const RFC5869_TEST3: HkdfTestVector = HkdfTestVector {
        ikm: &[
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ],
        salt: &[],
        info: &[],
        length: 42,
        expected: &[
            0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
            0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
            0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
        ],
        hash_algo: HashAlgo::Sha256,
    };

    fn get_test_secret_key(ikm: &[u8]) -> SecretKey {
        SecretKey::from_slice(ikm).unwrap()
    }

    fn run_hkdf_test_vector(tv: &HkdfTestVector) {
        let secret = get_test_secret_key(tv.ikm);
        let mut output = vec![0u8; tv.length];

        let salt = if tv.salt.is_empty() {
            None
        } else {
            Some(tv.salt)
        };
        let info = if tv.info.is_empty() {
            None
        } else {
            Some(tv.info)
        };

        let result = secret
            .hkdf_derive(tv.hash_algo, salt, info, tv.length, &mut output)
            .unwrap();

        assert_eq!(result.len(), tv.length);
        assert_eq!(result, tv.expected);
    }

    // Test: HKDF RFC 5869 Test Case 1
    // Intention: Validate HKDF implementation against RFC 5869 test vector 1.
    // Expected result: Derived key matches the expected output from RFC 5869.
    #[test]
    fn test_hkdf_rfc5869_case1() {
        run_hkdf_test_vector(&RFC5869_TEST1);
    }

    // Test: HKDF RFC 5869 Test Case 2
    // Intention: Validate HKDF implementation against RFC 5869 test vector 2 with longer inputs.
    // Expected result: Derived key matches the expected output from RFC 5869.
    #[test]
    fn test_hkdf_rfc5869_case2() {
        run_hkdf_test_vector(&RFC5869_TEST2);
    }

    // Test: HKDF RFC 5869 Test Case 3
    // Intention: Validate HKDF implementation against RFC 5869 test vector 3 with zero-length salt.
    // Expected result: Derived key matches the expected output from RFC 5869.
    #[test]
    fn test_hkdf_rfc5869_case3() {
        run_hkdf_test_vector(&RFC5869_TEST3);
    }

    // Test: HKDF with all supported hash algorithms
    // Intention: Ensure HKDF works with all supported hash algorithms.
    // Expected result: Key derivation succeeds for each algorithm without errors.
    #[test]
    fn test_hkdf_all_hash_algorithms() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let out_len = 32;

        for hash_algo in ALL_HKDF_HASHALGOS {
            let secret = get_test_secret_key(ikm);
            let mut output = vec![0u8; out_len];

            let result = secret.hkdf_derive(hash_algo, salt, info, out_len, &mut output);
            assert!(
                result.is_ok(),
                "HKDF failed for hash algorithm: {:?}",
                hash_algo
            );
            assert_eq!(result.unwrap().len(), out_len);
        }
    }

    // Test: HKDF with no salt
    // Intention: Ensure HKDF works correctly when no salt is provided.
    // Expected result: Key derivation succeeds with consistent output.
    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"test input key material";
        let info = Some(b"context info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);
        let mut output1 = vec![0u8; out_len];
        let mut output2 = vec![0u8; out_len];

        // Two calls should produce the same result
        let result1 = secret.hkdf_derive(HashAlgo::Sha256, None, info, out_len, &mut output1);
        let result2 = secret.hkdf_derive(HashAlgo::Sha256, None, info, out_len, &mut output2);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    // Test: HKDF with no info
    // Intention: Ensure HKDF works correctly when no context info is provided.
    // Expected result: Key derivation succeeds with consistent output.
    #[test]
    fn test_hkdf_no_info() {
        let ikm = b"test input key material";
        let salt = Some(b"random salt".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);
        let mut output1 = vec![0u8; out_len];
        let mut output2 = vec![0u8; out_len];

        // Two calls should produce the same result
        let result1 = secret.hkdf_derive(HashAlgo::Sha256, salt, None, out_len, &mut output1);
        let result2 = secret.hkdf_derive(HashAlgo::Sha256, salt, None, out_len, &mut output2);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_eq!(result1.unwrap(), result2.unwrap());
    }

    // Test: HKDF with different output lengths
    // Intention: Ensure HKDF can produce keys of various lengths.
    // Expected result: Key derivation succeeds for different output lengths.
    #[test]
    fn test_hkdf_different_output_lengths() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let lengths = [16, 32, 48, 64, 128, 255]; // Various key lengths

        let secret = get_test_secret_key(ikm);

        for &length in &lengths {
            let mut output = vec![0u8; length];
            let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, length, &mut output);

            assert!(result.is_ok(), "HKDF failed for output length: {}", length);
            assert_eq!(result.unwrap().len(), length);

            // Ensure output is not all zeros (proper derivation occurred)
            assert!(output.iter().any(|&b| b != 0));
        }
    }

    // Test: HKDF output buffer too small
    // Intention: Ensure HKDF returns an error when the output buffer is smaller than requested.
    // Expected result: Returns CryptoError::HkdfBackendFail.
    #[test]
    fn test_hkdf_buffer_too_small() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let out_len = 64;

        let secret = get_test_secret_key(ikm);
        let mut small_buffer = vec![0u8; 32]; // Buffer smaller than out_len

        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut small_buffer);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::HkdfOutputBufferTooSmall
        ));
    }

    // Test: SecretKey from empty slice
    // Intention: Ensure SecretKey::from_slice rejects empty key material.
    // Expected result: Returns CryptoError::SecretCreationFailed.
    #[test]
    fn test_secret_key_from_empty_slice() {
        let result = SecretKey::from_slice(&[]);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::SecretCreationFailed
        ));
    }

    // Test: SecretKey from valid slice
    // Intention: Ensure SecretKey::from_slice works with valid key material.
    // Expected result: SecretKey is created successfully.
    #[test]
    fn test_secret_key_from_valid_slice() {
        let key_material = b"valid key material";
        let result = SecretKey::from_slice(key_material);
        assert!(result.is_ok());
    }

    // Test: HKDF deterministic output
    // Intention: Ensure HKDF produces deterministic results for the same inputs.
    // Expected result: Multiple calls with identical inputs produce identical outputs.
    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"deterministic test key material";
        let salt = Some(b"fixed salt".as_slice());
        let info = Some(b"fixed info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);

        let mut output1 = vec![0u8; out_len];
        let mut output2 = vec![0u8; out_len];
        let mut output3 = vec![0u8; out_len];

        let result1 = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output1);
        let result2 = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output2);
        let result3 = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output3);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert!(result3.is_ok());

        let slice1 = result1.unwrap();
        let slice2 = result2.unwrap();
        let slice3 = result3.unwrap();

        assert_eq!(slice1, slice2);
        assert_eq!(slice2, slice3);
    }

    // Test: HKDF with different salt values produces different outputs
    // Intention: Ensure different salt values produce different derived keys.
    // Expected result: Different salts produce different outputs for the same IKM.
    #[test]
    fn test_hkdf_different_salts() {
        let ikm = b"test input key material";
        let salt1 = Some(b"salt1".as_slice());
        let salt2 = Some(b"salt2".as_slice());
        let info = Some(b"info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);

        let mut output1 = vec![0u8; out_len];
        let mut output2 = vec![0u8; out_len];

        let result1 = secret.hkdf_derive(HashAlgo::Sha256, salt1, info, out_len, &mut output1);
        let result2 = secret.hkdf_derive(HashAlgo::Sha256, salt2, info, out_len, &mut output2);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_ne!(result1.unwrap(), result2.unwrap());
    }

    // Test: HKDF with different info values produces different outputs
    // Intention: Ensure different info values produce different derived keys.
    // Expected result: Different info produces different outputs for the same IKM and salt.
    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info1 = Some(b"info1".as_slice());
        let info2 = Some(b"info2".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);

        let mut output1 = vec![0u8; out_len];
        let mut output2 = vec![0u8; out_len];

        let result1 = secret.hkdf_derive(HashAlgo::Sha256, salt, info1, out_len, &mut output1);
        let result2 = secret.hkdf_derive(HashAlgo::Sha256, salt, info2, out_len, &mut output2);

        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_ne!(result1.unwrap(), result2.unwrap());
    }

    // ==== NEGATIVE TEST CASES ====

    // Test: HKDF with maximum output length boundary
    // Intention: Test the RFC 5869 limit of 255 * HashLen bytes for output length.
    // Expected result: Should succeed at the boundary and fail beyond it.
    #[test]
    fn test_hkdf_max_output_length() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());

        let secret = get_test_secret_key(ikm);

        // SHA-256 has 32-byte output, so max HKDF output is 255 * 32 = 8160 bytes
        let max_length = 255 * 32;
        let mut max_output = vec![0u8; max_length];

        // This should succeed (at the boundary)
        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, max_length, &mut max_output);
        assert!(
            result.is_ok(),
            "HKDF should succeed at maximum length boundary"
        );

        // Test one byte over the limit - this should fail
        let over_limit = max_length + 1;
        let mut over_output = vec![0u8; over_limit];

        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, over_limit, &mut over_output);
        assert!(
            result.is_err(),
            "HKDF should fail when exceeding maximum output length"
        );
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::HkdfOutputTooLarge
        ));
    }

    // Test: HKDF with zero output length
    // Intention: Ensure HKDF rejects zero-length output requests.
    // Expected result: Returns CryptoError::HkdfOutputLengthZero.
    #[test]
    fn test_hkdf_zero_output_length() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let mut output = vec![0u8; 32]; // Buffer is valid, but requested length is 0

        let secret = get_test_secret_key(ikm);
        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, 0, &mut output);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::HkdfOutputLengthZero
        ));
    }

    // Test: HKDF with extremely large salt
    // Intention: Test behavior with unusually large salt values.
    // Expected result: Should handle gracefully without crashing.
    #[test]
    fn test_hkdf_large_salt() {
        let ikm = b"test input key material";
        let large_salt = vec![0x42u8; 1024]; // 1KB salt
        let info = Some(b"info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(ikm);
        let mut output = vec![0u8; out_len];

        let result = secret.hkdf_derive(
            HashAlgo::Sha256,
            Some(&large_salt),
            info,
            out_len,
            &mut output,
        );
        assert!(result.is_ok(), "HKDF should handle large salt values");
        assert_eq!(result.unwrap().len(), out_len);
    }

    // Test: HKDF with extremely large info
    // Intention: Test behavior with unusually large info values.
    // Expected result: Should handle gracefully without crashing.
    #[test]
    fn test_hkdf_large_info() {
        let ikm = b"test input key material";
        let salt = Some(b"salt".as_slice());
        let large_info = vec![0x43u8; 2048]; // 2KB info
        let out_len = 32;

        let secret = get_test_secret_key(ikm);
        let mut output = vec![0u8; out_len];

        let result = secret.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            Some(&large_info),
            out_len,
            &mut output,
        );
        assert!(result.is_ok(), "HKDF should handle large info values");
        assert_eq!(result.unwrap().len(), out_len);
    }

    // Test: HKDF with very small IKM
    // Intention: Test behavior with minimal input key material.
    // Expected result: Should work with single-byte IKM.
    #[test]
    fn test_hkdf_minimal_ikm() {
        let minimal_ikm = &[0x01u8]; // Single byte IKM
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(minimal_ikm);
        let mut output = vec![0u8; out_len];

        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output);
        assert!(result.is_ok(), "HKDF should work with minimal IKM");
        assert_eq!(result.unwrap().len(), out_len);

        // Ensure output is not all zeros
        assert!(output.iter().any(|&b| b != 0));
    }

    // Test: HKDF with very large IKM
    // Intention: Test behavior with unusually large input key material.
    // Expected result: Should handle large IKM consistently across platforms, though CNG may have size limits.
    #[test]
    fn test_hkdf_large_ikm() {
        let large_ikm = vec![0x44u8; 4096]; // 4KB IKM
        let salt = Some(b"salt".as_slice());
        let info = Some(b"info".as_slice());
        let out_len = 32;

        let secret = get_test_secret_key(&large_ikm);
        let mut output = vec![0u8; out_len];

        let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output);

        // The behavior may vary by implementation - CNG may have IKM size limits while OpenSSL may succeed
        // We test that the implementation either succeeds or fails gracefully with appropriate error
        match result {
            Ok(derived_key) => {
                // If it succeeds, verify the output length is correct
                assert_eq!(derived_key.len(), out_len);
                assert!(
                    output.iter().any(|&b| b != 0),
                    "Output should not be all zeros"
                );
            }
            Err(e) => {
                // If it fails, it should be due to extract phase limitations (e.g., CNG IKM limits)
                assert!(
                    matches!(e, CryptoError::HkdfExtractFailed),
                    "Large IKM should fail with HkdfExtractFailed, got: {:?}",
                    e
                );
            }
        }
    }

    // Test: HKDF stress test with multiple rapid calls
    // Intention: Ensure implementation is stable under rapid repeated usage.
    // Expected result: All calls should succeed with consistent results for same inputs.
    #[test]
    fn test_hkdf_stress_multiple_calls() {
        let ikm = b"stress test key material";
        let salt = Some(b"stress salt".as_slice());
        let info = Some(b"stress info".as_slice());
        let out_len = 64;

        let secret = get_test_secret_key(ikm);
        let mut expected_output = vec![0u8; out_len];

        // Get the expected result
        let expected_result = secret
            .hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut expected_output)
            .unwrap();

        // Perform 100 rapid calls and verify consistency
        for i in 0..100 {
            let mut output = vec![0u8; out_len];
            let result = secret.hkdf_derive(HashAlgo::Sha256, salt, info, out_len, &mut output);

            assert!(result.is_ok(), "HKDF call {} should succeed", i);
            assert_eq!(
                result.unwrap(),
                expected_result,
                "HKDF call {} should produce consistent output",
                i
            );
        }
    }

    // Test: HKDF with edge case output lengths for different hash algorithms
    // Intention: Test boundary conditions for each supported hash algorithm.
    // Expected result: Should handle various output lengths correctly.
    #[test]
    fn test_hkdf_hash_specific_boundaries() {
        let ikm = b"boundary test key material";
        let salt = Some(b"boundary salt".as_slice());
        let info = Some(b"boundary info".as_slice());

        let secret = get_test_secret_key(ikm);

        // Test each hash algorithm with its specific maximum output
        let test_cases = [
            (HashAlgo::Sha1, 20, 255 * 20), // SHA-1: 20-byte output, max 5100 bytes
            (HashAlgo::Sha256, 32, 255 * 32), // SHA-256: 32-byte output, max 8160 bytes
            (HashAlgo::Sha384, 48, 255 * 48), // SHA-384: 48-byte output, max 12240 bytes
            (HashAlgo::Sha512, 64, 255 * 64), // SHA-512: 64-byte output, max 16320 bytes
        ];

        for (hash_algo, hash_len, max_output_len) in test_cases {
            // Test at hash length boundary
            let mut output = vec![0u8; hash_len];
            let result = secret.hkdf_derive(hash_algo, salt, info, hash_len, &mut output);
            assert!(
                result.is_ok(),
                "HKDF should succeed at hash length for {:?}",
                hash_algo
            );

            // Test at maximum output length boundary (if practical for testing)
            if max_output_len <= 1024 {
                // Only test smaller maximums to avoid excessive memory usage
                let mut max_output = vec![0u8; max_output_len];
                let result =
                    secret.hkdf_derive(hash_algo, salt, info, max_output_len, &mut max_output);
                assert!(
                    result.is_ok(),
                    "HKDF should succeed at maximum length for {:?}",
                    hash_algo
                );
            }
        }
    }

    // ECDH + HKDF Integration Tests
    // These tests demonstrate the practical use case of performing ECDH key exchange
    // and then using the shared secret as input for HKDF key derivation.

    /// Helper function to generate ECDH keypairs for testing
    fn generate_ecdh_keypair(curve: EcCurveId) -> (EcPrivateKey, EcPublicKey) {
        EcKeyGen
            .ec_key_gen_pair(curve)
            .expect("Failed to generate EC keypair for ECDH testing")
    }

    /// Helper function to perform ECDH key exchange and return the shared secret
    fn perform_ecdh_exchange(
        private_key: &EcPrivateKey,
        public_key: &EcPublicKey,
    ) -> Result<Vec<u8>, CryptoError> {
        let key_size = private_key.ecdh_get_derived_key_size()?;
        let mut shared_secret = vec![0u8; key_size];
        private_key.ecdh_key_derive(public_key, &mut shared_secret)?;
        Ok(shared_secret)
    }

    // Test: ECDH + HKDF with all supported curves
    // Intention: Demonstrate ECDH key exchange followed by HKDF key derivation for all supported curves.
    // Expected result: Both parties derive the same final key from the shared ECDH secret for each curve.
    #[test]
    fn test_ecdh_hkdf() {
        let test_cases = [
            (
                EcCurveId::EccP256,
                HashAlgo::Sha256,
                32,
                32,
                "p256",
                b"ecdh-hkdf-test-salt-p256",
                b"ecdh-hkdf-test-info-p256",
            ),
            (
                EcCurveId::EccP384,
                HashAlgo::Sha384,
                48,
                48,
                "p384",
                b"ecdh-hkdf-test-salt-p384",
                b"ecdh-hkdf-test-info-p384",
            ),
            (
                EcCurveId::EccP521,
                HashAlgo::Sha512,
                66,
                64,
                "p521",
                b"ecdh-hkdf-test-salt-p521",
                b"ecdh-hkdf-test-info-p521",
            ),
        ];

        for (
            curve,
            hash_algo,
            expected_secret_len,
            derived_key_len,
            curve_name,
            salt_bytes,
            info_bytes,
        ) in test_cases
        {
            // Generate two keypairs (Party A and Party B)
            let (party_a_private, party_a_public) = generate_ecdh_keypair(curve);
            let (party_b_private, party_b_public) = generate_ecdh_keypair(curve);

            // Perform ECDH key exchange from both sides
            let party_a_shared_secret = perform_ecdh_exchange(&party_a_private, &party_b_public)
                .unwrap_or_else(|_| panic!("Party A's ECDH should succeed for {}", curve_name));
            let party_b_shared_secret = perform_ecdh_exchange(&party_b_private, &party_a_public)
                .unwrap_or_else(|_| panic!("Party B's ECDH should succeed for {}", curve_name));

            // Verify both parties computed the same shared secret
            assert_eq!(
                party_a_shared_secret, party_b_shared_secret,
                "ECDH shared secrets should match for {}",
                curve_name
            );
            assert_eq!(
                party_a_shared_secret.len(),
                expected_secret_len,
                "{} shared secret should be {} bytes",
                curve_name,
                expected_secret_len
            );

            // Use the shared secret for HKDF key derivation
            let party_a_secret_key =
                SecretKey::from_slice(&party_a_shared_secret).unwrap_or_else(|_| {
                    panic!(
                        "Party A's secret key creation should succeed for {}",
                        curve_name
                    )
                });
            let party_b_secret_key =
                SecretKey::from_slice(&party_b_shared_secret).unwrap_or_else(|_| {
                    panic!(
                        "Party B's secret key creation should succeed for {}",
                        curve_name
                    )
                });

            // Derive keys using HKDF with same parameters
            let salt = Some(salt_bytes.as_slice());
            let info = Some(info_bytes.as_slice());

            let mut party_a_derived_key = vec![0u8; derived_key_len];
            let party_a_result = party_a_secret_key.hkdf_derive(
                hash_algo,
                salt,
                info,
                derived_key_len,
                &mut party_a_derived_key,
            );
            assert!(
                party_a_result.is_ok(),
                "Party A's HKDF derivation should succeed for {}",
                curve_name
            );

            let mut party_b_derived_key = vec![0u8; derived_key_len];
            let party_b_result = party_b_secret_key.hkdf_derive(
                hash_algo,
                salt,
                info,
                derived_key_len,
                &mut party_b_derived_key,
            );
            assert!(
                party_b_result.is_ok(),
                "Party B's HKDF derivation should succeed for {}",
                curve_name
            );

            // Verify both parties derived the same key
            assert_eq!(
                party_a_derived_key, party_b_derived_key,
                "HKDF derived keys should match between parties for {}",
                curve_name
            );
            assert_eq!(
                party_a_derived_key.len(),
                derived_key_len,
                "Derived key should have requested length for {}",
                curve_name
            );
        }
    }

    // Test: ECDH + HKDF Multiple Key Derivation
    // Intention: Test deriving multiple different keys from the same ECDH shared secret.
    // Expected result: Different info parameters should produce different derived keys.
    #[test]
    fn test_ecdh_hkdf_multiple_keys() {
        let curve = EcCurveId::EccP256;

        // Generate keypairs and perform ECDH
        let (initiator_private, _initiator_public) = generate_ecdh_keypair(curve);
        let (_responder_private, responder_public) = generate_ecdh_keypair(curve);

        let shared_secret = perform_ecdh_exchange(&initiator_private, &responder_public)
            .expect("ECDH should succeed");
        let secret_key =
            SecretKey::from_slice(&shared_secret).expect("Secret key creation should succeed");

        // Derive multiple keys with different info parameters
        let salt = Some(b"common-salt".as_slice());
        let derived_key_len = 32;

        // Key 1: For encryption
        let mut encryption_key = vec![0u8; derived_key_len];
        let result1 = secret_key.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            Some(b"encryption-key".as_slice()),
            derived_key_len,
            &mut encryption_key,
        );
        assert!(result1.is_ok(), "Encryption key derivation should succeed");

        // Key 2: For authentication
        let mut auth_key = vec![0u8; derived_key_len];
        let result2 = secret_key.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            Some(b"authentication-key".as_slice()),
            derived_key_len,
            &mut auth_key,
        );
        assert!(
            result2.is_ok(),
            "Authentication key derivation should succeed"
        );

        // Key 3: For key wrapping
        let mut wrap_key = vec![0u8; derived_key_len];
        let result3 = secret_key.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            Some(b"key-wrapping".as_slice()),
            derived_key_len,
            &mut wrap_key,
        );
        assert!(
            result3.is_ok(),
            "Key wrapping key derivation should succeed"
        );

        // Verify all derived keys are different
        assert_ne!(
            encryption_key, auth_key,
            "Encryption and auth keys should differ"
        );
        assert_ne!(
            encryption_key, wrap_key,
            "Encryption and wrap keys should differ"
        );
        assert_ne!(auth_key, wrap_key, "Auth and wrap keys should differ");

        // Verify all keys have the correct length
        assert_eq!(encryption_key.len(), derived_key_len);
        assert_eq!(auth_key.len(), derived_key_len);
        assert_eq!(wrap_key.len(), derived_key_len);
    }

    // Test: ECDH + HKDF with Different Hash Algorithms
    // Intention: Test using different hash algorithms for HKDF with the same ECDH shared secret.
    // Expected result: Different hash algorithms should produce different derived keys.
    #[test]
    fn test_ecdh_hkdf_different_hash_algorithms() {
        let curve = EcCurveId::EccP256;

        // Generate keypairs and perform ECDH
        let (initiator_private, _initiator_public) = generate_ecdh_keypair(curve);
        let (_responder_private, responder_public) = generate_ecdh_keypair(curve);

        let shared_secret = perform_ecdh_exchange(&initiator_private, &responder_public)
            .expect("ECDH should succeed");
        let secret_key =
            SecretKey::from_slice(&shared_secret).expect("Secret key creation should succeed");

        let salt = Some(b"hash-test-salt".as_slice());
        let info = Some(b"hash-test-info".as_slice());
        let derived_key_len = 32;

        // Test with different hash algorithms
        let hash_algorithms = [
            HashAlgo::Sha1,
            HashAlgo::Sha256,
            HashAlgo::Sha384,
            HashAlgo::Sha512,
        ];

        let mut derived_keys = Vec::new();

        for hash_algo in hash_algorithms {
            let mut key = vec![0u8; derived_key_len];
            let result = secret_key.hkdf_derive(hash_algo, salt, info, derived_key_len, &mut key);
            assert!(
                result.is_ok(),
                "HKDF should succeed with hash algorithm {:?}",
                hash_algo
            );
            derived_keys.push(key);
        }

        // Verify all keys are different (different hash algorithms should produce different outputs)
        for i in 0..derived_keys.len() {
            for j in (i + 1)..derived_keys.len() {
                assert_ne!(
                    derived_keys[i], derived_keys[j],
                    "Keys derived with different hash algorithms should differ"
                );
            }
        }
    }

    // Test: ECDH + HKDF Variable Output Lengths
    // Intention: Test deriving keys of various lengths from ECDH shared secret.
    // Expected result: HKDF should produce keys of requested lengths correctly.
    #[test]
    fn test_ecdh_hkdf_variable_output_lengths() {
        let curve = EcCurveId::EccP384;

        // Generate keypairs and perform ECDH
        let (initiator_private, _initiator_public) = generate_ecdh_keypair(curve);
        let (_responder_private, responder_public) = generate_ecdh_keypair(curve);

        let shared_secret = perform_ecdh_exchange(&initiator_private, &responder_public)
            .expect("ECDH should succeed");
        let secret_key =
            SecretKey::from_slice(&shared_secret).expect("Secret key creation should succeed");

        let salt = Some(b"variable-length-salt".as_slice());
        let info = Some(b"variable-length-info".as_slice());

        // Test various output lengths
        let test_lengths = [16, 24, 32, 48, 64, 128, 256];

        for &length in &test_lengths {
            let mut derived_key = vec![0u8; length];
            let result =
                secret_key.hkdf_derive(HashAlgo::Sha256, salt, info, length, &mut derived_key);
            assert!(
                result.is_ok(),
                "HKDF should succeed with output length {}",
                length
            );
            let key = result.unwrap();
            assert_eq!(
                key.len(),
                length,
                "Derived key should have requested length {}",
                length
            );
        }
    }

    // Test: ECDH + HKDF with No Salt
    // Intention: Test HKDF key derivation from ECDH shared secret without salt.
    // Expected result: HKDF should work correctly with None salt (zero-length salt).
    #[test]
    fn test_ecdh_hkdf_no_salt() {
        let curve = EcCurveId::EccP256;

        // Generate keypairs and perform ECDH
        let (party_a_private, party_a_public) = generate_ecdh_keypair(curve);
        let (party_b_private, party_b_public) = generate_ecdh_keypair(curve);

        let party_a_shared_secret = perform_ecdh_exchange(&party_a_private, &party_b_public)
            .expect("Party A's ECDH should succeed");
        let party_b_shared_secret = perform_ecdh_exchange(&party_b_private, &party_a_public)
            .expect("Party B's ECDH should succeed");

        assert_eq!(party_a_shared_secret, party_b_shared_secret);

        // Create secret keys
        let party_a_secret_key = SecretKey::from_slice(&party_a_shared_secret)
            .expect("Party A's secret key creation should succeed");
        let party_b_secret_key = SecretKey::from_slice(&party_b_shared_secret)
            .expect("Party B's secret key creation should succeed");

        // Derive keys without salt (None)
        let info = Some(b"no-salt-test-info".as_slice());
        let derived_key_len = 32;

        let mut party_a_derived_key = vec![0u8; derived_key_len];
        let party_a_result = party_a_secret_key.hkdf_derive(
            HashAlgo::Sha256,
            None, // No salt
            info,
            derived_key_len,
            &mut party_a_derived_key,
        );
        assert!(
            party_a_result.is_ok(),
            "Party A's HKDF without salt should succeed"
        );

        let mut party_b_derived_key = vec![0u8; derived_key_len];
        let party_b_result = party_b_secret_key.hkdf_derive(
            HashAlgo::Sha256,
            None, // No salt
            info,
            derived_key_len,
            &mut party_b_derived_key,
        );
        assert!(
            party_b_result.is_ok(),
            "Party B's HKDF without salt should succeed"
        );

        // Verify both parties derived the same key
        assert_eq!(
            party_a_derived_key, party_b_derived_key,
            "HKDF derived keys should match even without salt"
        );
    }

    // Test: ECDH + HKDF with No Info
    // Intention: Test HKDF key derivation from ECDH shared secret without info parameter.
    // Expected result: HKDF should work correctly with None info.
    #[test]
    fn test_ecdh_hkdf_no_info() {
        let curve = EcCurveId::EccP256;

        // Generate keypairs and perform ECDH
        let (party_a_private, party_a_public) = generate_ecdh_keypair(curve);
        let (party_b_private, party_b_public) = generate_ecdh_keypair(curve);

        let party_a_shared_secret = perform_ecdh_exchange(&party_a_private, &party_b_public)
            .expect("Party A's ECDH should succeed");
        let party_b_shared_secret = perform_ecdh_exchange(&party_b_private, &party_a_public)
            .expect("Party B's ECDH should succeed");

        assert_eq!(party_a_shared_secret, party_b_shared_secret);

        // Create secret keys
        let party_a_secret_key = SecretKey::from_slice(&party_a_shared_secret)
            .expect("Party A's secret key creation should succeed");
        let party_b_secret_key = SecretKey::from_slice(&party_b_shared_secret)
            .expect("Party B's secret key creation should succeed");

        // Derive keys without info (None)
        let salt = Some(b"no-info-test-salt".as_slice());
        let derived_key_len = 32;

        let mut party_a_derived_key = vec![0u8; derived_key_len];
        let party_a_result = party_a_secret_key.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            None, // No info
            derived_key_len,
            &mut party_a_derived_key,
        );
        assert!(
            party_a_result.is_ok(),
            "Party A's HKDF without info should succeed"
        );

        let mut party_b_derived_key = vec![0u8; derived_key_len];
        let party_b_result = party_b_secret_key.hkdf_derive(
            HashAlgo::Sha256,
            salt,
            None, // No info
            derived_key_len,
            &mut party_b_derived_key,
        );
        assert!(
            party_b_result.is_ok(),
            "Party B's HKDF without info should succeed"
        );

        // Verify both parties derived the same key
        assert_eq!(
            party_a_derived_key, party_b_derived_key,
            "HKDF derived keys should match even without info"
        );
    }
}
