// Copyright (C) Microsoft Corporation. All rights reserved.
use super::*;

/// Converts test vector hash algorithm enum to runtime Hash object.
impl From<TestHashAlgo> for HashAlgo {
    fn from(hash_algo: TestHashAlgo) -> Self {
        match hash_algo {
            TestHashAlgo::Sha1 => HashAlgo::sha1(),
            TestHashAlgo::Sha256 => HashAlgo::sha256(),
            TestHashAlgo::Sha384 => HashAlgo::sha384(),
            TestHashAlgo::Sha512 => HashAlgo::sha512(),
        }
    }
}

/// Helper function to extract bytes from a GenericSecretKey.
fn extract_key_bytes(key: &GenericSecretKey, context: &str) -> Vec<u8> {
    let key_len = key
        .to_bytes(None)
        .unwrap_or_else(|_| panic!("{} length failed", context));
    let mut key_bytes = vec![0u8; key_len];
    key.to_bytes(Some(&mut key_bytes))
        .unwrap_or_else(|_| panic!("Extract {} bytes failed", context));
    key_bytes
}

/// Common HKDF derivation function for test vectors.
///
/// Performs HKDF derivation with the specified mode and returns the derived key bytes.
/// Automatically selects the appropriate input key, salt, and info based on mode.
///
/// # Arguments
///
/// * `vec` - Test vector containing IKM, salt, info, PRK, and expected output
/// * `mode` - HKDF derivation mode (Extract, Expand, or ExtractAndExpand)
/// * `expected_length` - Expected length of derived key material
///
/// # Returns
///
/// Vector of derived key bytes.
fn derive_with_mode(vec: &HkdfTestVector, mode: HkdfMode, expected_length: usize) -> Vec<u8> {
    // Select input key based on mode
    let input_key = match mode {
        HkdfMode::Expand => {
            // Expand takes PRK as input
            GenericSecretKey::from_bytes(vec.prk).expect("Create PRK key failed")
        }
        _ => {
            // Extract modes take IKM as input
            GenericSecretKey::from_bytes(vec.ikm).expect("Create IKM key failed")
        }
    };

    // Configure parameters based on mode
    let (salt, info) = match mode {
        HkdfMode::Extract => (Some(vec.salt), None),
        HkdfMode::Expand => (None, Some(vec.info)),
        HkdfMode::ExtractAndExpand => (Some(vec.salt), Some(vec.info)),
    };

    // Create HKDF instance
    let hash: HashAlgo = vec.hash_algo.into();
    let hkdf = HkdfAlgo::new(mode, &hash, salt, info);

    // Derive and extract bytes
    let derived_key = hkdf
        .derive(&input_key, expected_length)
        .expect("HKDF derivation failed");
    extract_key_bytes(&derived_key, "derived key")
}

/// Helper function for testing HKDF with custom inputs.
///
/// Creates HKDF instance, performs derivation, and returns the output bytes.
///
/// # Arguments
///
/// * `hash` - Hash algorithm to use
/// * `mode` - HKDF derivation mode
/// * `ikm` - Input keying material
/// * `salt` - Optional salt
/// * `info` - Optional info
/// * `length` - Desired output length
///
/// # Returns
///
/// Vector of derived key bytes.
fn hkdf_derive(
    hash: &HashAlgo,
    mode: HkdfMode,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    length: usize,
) -> Vec<u8> {
    let key = GenericSecretKey::from_bytes(ikm).expect("Create key failed");
    let hkdf = HkdfAlgo::new(mode, hash, salt, info);
    let output = hkdf.derive(&key, length).expect("HKDF derivation failed");
    extract_key_bytes(&output, "output")
}

#[test]
fn test_hkdf_rfc_vectors() {
    for (i, vec) in RFC5869_TEST_VECTORS.iter().enumerate() {
        let output = derive_with_mode(vec, HkdfMode::ExtractAndExpand, vec.length);

        assert_eq!(
            output.len(),
            vec.length,
            "Derived key length mismatch for test vector {}",
            i
        );

        assert_eq!(
            &output, vec.expected,
            "HKDF output does not match expected for test vector {}",
            i
        );
    }
}

#[test]
fn test_hkdf_extract_only() {
    for (i, vec) in RFC5869_TEST_VECTORS.iter().enumerate() {
        let prk_output = derive_with_mode(vec, HkdfMode::Extract, vec.prk.len());

        assert_eq!(
            prk_output.len(),
            vec.prk.len(),
            "PRK length mismatch for test vector {}",
            i
        );

        assert_eq!(
            &prk_output, vec.prk,
            "HKDF PRK does not match expected for test vector {}",
            i
        );
    }
}

#[test]
fn test_hkdf_expand_only() {
    for (i, vec) in RFC5869_TEST_VECTORS.iter().take(1).enumerate() {
        let okm_output = derive_with_mode(vec, HkdfMode::Expand, vec.length);

        assert_eq!(
            okm_output.len(),
            vec.length,
            "OKM length mismatch for test vector {}",
            i
        );

        assert_eq!(
            &okm_output, vec.expected,
            "HKDF OKM does not match expected for test vector {}",
            i
        );
    }
}

#[test]
fn test_hkdf_sha384_extract_then_expand() {
    let ikm = &[0x0b; 22];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 48;
    let hash = HashAlgo::sha384();

    let output = hkdf_derive(
        &hash,
        HkdfMode::ExtractAndExpand,
        ikm,
        Some(salt),
        Some(info),
        length,
    );

    assert_eq!(output.len(), length, "SHA-384 output length mismatch");
}

#[test]
fn test_hkdf_sha384_extract_only() {
    let ikm = &[0x0b; 22];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let hash = HashAlgo::sha384();

    let prk = hkdf_derive(&hash, HkdfMode::Extract, ikm, Some(salt), None, 48);

    assert_eq!(prk.len(), 48, "SHA-384 PRK length should be 48 bytes");
}

#[test]
fn test_hkdf_sha384_expand_only() {
    let ikm = &[0x0b; 22];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 48;
    let hash = HashAlgo::sha384();

    // First extract PRK
    let prk = hkdf_derive(&hash, HkdfMode::Extract, ikm, Some(salt), None, 48);

    // Then expand using PRK
    let expanded = hkdf_derive(&hash, HkdfMode::Expand, &prk, None, Some(info), length);

    // Should match full HKDF
    let full_output = hkdf_derive(
        &hash,
        HkdfMode::ExtractAndExpand,
        ikm,
        Some(salt),
        Some(info),
        length,
    );

    assert_eq!(expanded.len(), length, "SHA-384 expanded length mismatch");
    assert_eq!(
        &expanded, &full_output,
        "SHA-384 Expand should match ExtractAndExpand"
    );
}

#[test]
fn test_hkdf_sha512_extract_then_expand() {
    let ikm = &[0x0b; 32];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 64;
    let hash = HashAlgo::sha512();

    let output = hkdf_derive(
        &hash,
        HkdfMode::ExtractAndExpand,
        ikm,
        Some(salt),
        Some(info),
        length,
    );

    assert_eq!(output.len(), length, "SHA-512 output length mismatch");
}

#[test]
fn test_hkdf_sha512_extract_only() {
    let ikm = &[0x0b; 32];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let hash = HashAlgo::sha512();

    let prk = hkdf_derive(&hash, HkdfMode::Extract, ikm, Some(salt), None, 64);

    assert_eq!(prk.len(), 64, "SHA-512 PRK length should be 64 bytes");
}

#[test]
fn test_hkdf_sha512_expand_only() {
    let ikm = &[0x0b; 32];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 64;
    let hash = HashAlgo::sha512();

    // First extract PRK
    let prk = hkdf_derive(&hash, HkdfMode::Extract, ikm, Some(salt), None, 64);

    // Then expand using PRK
    let expanded = hkdf_derive(&hash, HkdfMode::Expand, &prk, None, Some(info), length);

    // Should match full HKDF
    let full_output = hkdf_derive(
        &hash,
        HkdfMode::ExtractAndExpand,
        ikm,
        Some(salt),
        Some(info),
        length,
    );

    assert_eq!(expanded.len(), length, "SHA-512 expanded length mismatch");
    assert_eq!(
        &expanded, &full_output,
        "SHA-512 Expand should match ExtractAndExpand"
    );
}

#[test]
fn test_hkdf_empty_salt() {
    // Test HKDF with empty salt (should still work, using hash-length zeros as default)
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0x0a; hash.size()];
        let length = hash.size();
        let output = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(&[]),
            Some(info),
            length,
        );

        assert_eq!(
            output.len(),
            length,
            "Empty salt output length mismatch for hash size {}",
            hash.size()
        );
    }
}

#[test]
fn test_hkdf_empty_info() {
    // Test HKDF with empty info parameter
    let salt = &[0x00, 0x01, 0x02, 0x03];
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0x0c; hash.size()];
        let length = hash.size();
        let output = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(&[]),
            length,
        );

        assert_eq!(
            output.len(),
            length,
            "Empty info output length mismatch for hash size {}",
            hash.size()
        );
    }
}

#[test]
fn test_hkdf_variable_output_lengths() {
    // Test HKDF with various output lengths across all algorithms
    let salt = &[0x00, 0x01, 0x02, 0x03];
    let info = &[0xf0, 0xf1];
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0xbb; hash.size()];
        for length in [16, 32, 48, 64, 80, 100] {
            let output = hkdf_derive(
                &hash,
                HkdfMode::ExtractAndExpand,
                &ikm,
                Some(salt),
                Some(info),
                length,
            );

            assert_eq!(
                output.len(),
                length,
                "Output length mismatch for hash size {} with requested length {}",
                hash.size(),
                length
            );
        }
    }
}

#[test]
fn test_hkdf_max_output_length() {
    // Test maximum output length for each algorithm: 255 * hash_length
    let salt = &[0x00, 0x01, 0x02, 0x03];
    let info = &[0xf0, 0xf1];
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0xaa; hash.size()];
        let length = 255 * hash.size();
        let output = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(info),
            length,
        );

        assert_eq!(
            output.len(),
            length,
            "Maximum output length mismatch for hash size {}",
            hash.size()
        );
    }
}

#[test]
fn test_hkdf_deterministic() {
    // Verify that HKDF produces deterministic output for same inputs across all algorithms
    let salt = &[0x00, 0x01, 0x02, 0x03];
    let info = &[0xf0, 0xf1, 0xf2];
    let length = 42;
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0xdd; hash.size()];
        let output1 = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(info),
            length,
        );

        let output2 = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(info),
            length,
        );

        assert_eq!(
            output1,
            output2,
            "HKDF should produce deterministic output for hash size {}",
            hash.size()
        );
    }
}

#[test]
fn test_hkdf_different_info_different_output() {
    // Verify that different info parameters produce different outputs across all algorithms
    let salt = &[0x00, 0x01, 0x02, 0x03];
    let info1 = &[0xf0, 0xf1, 0xf2];
    let info2 = &[0xf0, 0xf1, 0xf3]; // Different last byte
    let length = 32;
    let hashes = [
        HashAlgo::sha1(),
        HashAlgo::sha256(),
        HashAlgo::sha384(),
        HashAlgo::sha512(),
    ];

    for hash in hashes {
        let ikm = vec![0xee; hash.size()];
        let output1 = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(info1),
            length,
        );

        let output2 = hkdf_derive(
            &hash,
            HkdfMode::ExtractAndExpand,
            &ikm,
            Some(salt),
            Some(info2),
            length,
        );

        assert_ne!(
            output1,
            output2,
            "Different info should produce different outputs for hash size {}",
            hash.size()
        );
    }
}

#[test]
#[should_panic(expected = "HKDF derivation failed: HkdfDeriveError")]
fn test_hkdf_zero_length_output() {
    let ikm = &[0x0b; 22];
    let salt = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let length = 0;
    let hash = HashAlgo::sha256();

    hkdf_derive(
        &hash,
        HkdfMode::ExtractAndExpand,
        ikm,
        Some(salt),
        Some(info),
        length,
    );
}
