// Copyright (C) Microsoft Corporation. All rights reserved.

//! Tests for KBKDF (Key-Based Key Derivation Function) implementation.
//! Validates correctness against official NIST SP 800-108 test vectors

use super::*;

/// Helper function to create a GenericSecretKey from a byte pattern.
fn create_key(pattern: u8, size: usize) -> GenericSecretKey {
    GenericSecretKey::from_bytes(&vec![pattern; size]).expect("Failed to create key")
}

/// Helper function to derive key and extract bytes in one step.
fn derive_and_extract(
    hash_algo: HashAlgo,
    key: &GenericSecretKey,
    label: Option<Vec<u8>>,
    context: Option<Vec<u8>>,
    use_length: bool,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    let kbkdf = if use_length {
        KbkdfAlgo::with_len(hash_algo, label, context)
    } else {
        KbkdfAlgo::without_len(hash_algo, label, context)
    };
    let output = kbkdf.derive(key, output_len)?;
    output.to_vec()
}

/// Performs KBKDF derivation for a single test vector.
///
/// # Arguments
///
/// * `vec` - Test vector containing input key, label, context, and expected output
///
/// # Returns
///
/// Vector of derived key bytes.
fn derive_kbkdf(vec: &KbkdfTestVector) -> Vec<u8> {
    // Convert input key material
    let ki = GenericSecretKey::from_bytes(vec.ki).expect("Failed to create input key");

    // Convert hash algorithm
    let hash_algo: HashAlgo = vec.hash_algo.into();

    // Prepare label and context
    let label = if vec.label.is_empty() {
        None
    } else {
        Some(vec.label.to_vec())
    };
    let context = if vec.context.is_empty() {
        None
    } else {
        Some(vec.context.to_vec())
    };

    // Create KBKDF instance (use_length = false for NIST test vectors)
    let kbkdf = KbkdfAlgo::without_len(hash_algo, label, context);

    // Derive key
    let derived = kbkdf
        .derive(&ki, vec.ko.len())
        .expect("KBKDF derivation failed");

    // Extract and return bytes
    derived.to_vec().expect("Failed to extract key bytes")
}

/// Validates a single KBKDF test vector.
///
/// # Arguments
///
/// * `vec` - Test vector to validate
/// * `index` - Test vector index for error reporting
fn validate_kbkdf_vector(vec: &KbkdfTestVector, index: usize) {
    let derived = derive_kbkdf(vec);

    assert_eq!(
        derived.len(),
        vec.ko.len(),
        "Vector {}: Output length mismatch",
        index
    );

    assert_eq!(
        &derived[..],
        vec.ko,
        "Vector_id {}: Output mismatch\nExpected: {:02x?}\nGot:      {:02x?}",
        vec.vector_id,
        vec.ko,
        &derived[..]
    );
}
#[test]
fn test_kbkdf_derive_basic() {
    let base_key = [0x01u8; 64]; // Use max required for all algos
    let label = Some(b"label".to_vec());
    let context = Some(b"contextForDerive".to_vec());
    let out_len = 32;

    let key = GenericSecretKey::from_bytes(base_key.as_ref()).expect("Create a Base key failed");

    // Create KBKDF algorithm instance
    let hash_algo = HashAlgo::sha256();
    let kbkdf_algo = KbkdfAlgo::with_len(hash_algo, label, context);

    // Derive key
    let derived_key = kbkdf_algo
        .derive(&key, out_len)
        .expect("KBKDF derive failed");

    // Check derived key length
    assert_eq!(derived_key.size(), out_len);
}

/// Comprehensive NIST SP 800-108 test vector validation.
///
/// Tests all official NIST test vectors for KBKDF Counter Mode with
/// counter location BEFORE_FIXED. Validates correctness across multiple
/// hash algorithms and input combinations.

#[test]
fn test_kbkdf_sha1_nist_vectors() {
    for (index, vec) in KBKDF_HMAC_SHA1_TEST_VECTORS.iter().enumerate() {
        validate_kbkdf_vector(vec, index);
    }
}
#[test]
fn test_kbkdf_sha256_nist_vectors() {
    for (index, vec) in KBKDF_HMAC_SHA256_TEST_VECTORS.iter().enumerate() {
        validate_kbkdf_vector(vec, index);
    }
}
#[test]
fn test_kbkdf_sha384_nist_vectors() {
    for (index, vec) in KBKDF_HMAC_SHA384_TEST_VECTORS.iter().enumerate() {
        validate_kbkdf_vector(vec, index);
    }
}

#[test]
fn test_kbkdf_sha512_nist_vectors() {
    for (index, vec) in KBKDF_HMAC_SHA512_TEST_VECTORS.iter().enumerate() {
        validate_kbkdf_vector(vec, index);
    }
}

/// Negative Tests - Error Handling Validation
///
/// Test KBKDF with empty input key (zero-length key).
///
/// Expected: Should return KbkdfInvalidPrkLength error.
#[test]
fn test_kbkdf_empty_key() {
    let empty_key = GenericSecretKey::from_bytes(&[]).expect("Create empty key failed");
    let hash_algo = HashAlgo::sha256();
    let label = Some(b"label empty key".to_vec());
    let kbkdf = KbkdfAlgo::without_len(hash_algo, label, None);

    let result = kbkdf.derive(&empty_key, 16);

    assert!(result.is_err(), "Expected error for empty key");
    match result {
        Err(CryptoError::KbkdfInvalidKdkLength) => {
            // Expected error
        }
        Err(e) => panic!("Expected KbkdfInvalidKdkLength, got {:?}", e),
        Ok(_) => panic!("Expected error but derivation succeeded"),
    }
}

/// Test KBKDF with neither label nor context provided.
///
/// Expected: Should return KbkdfSetPropertyError.
#[test]
fn test_kbkdf_no_label_no_context() {
    let key = GenericSecretKey::from_bytes(&[0x42; 32]).expect("Create key failed");
    let hash_algo = HashAlgo::sha256();
    let kbkdf = KbkdfAlgo::without_len(hash_algo, None, None);

    let result = kbkdf.derive(&key, 16);

    assert!(
        result.is_err(),
        "Expected error when both label and context are None"
    );
    match result {
        Err(CryptoError::KbkdfSetPropertyError) => {
            // Expected error
        }
        Err(e) => panic!("Expected KbkdfSetPropertyError, got {:?}", e),
        Ok(_) => panic!("Expected error but derivation succeeded"),
    }
}

/// Test KBKDF with only label (no context) - should succeed.
#[test]
fn test_kbkdf_label_only() {
    let key = create_key(0x42, 32);
    let label = Some(b"test_label".to_vec());

    let result = derive_and_extract(HashAlgo::sha256(), &key, label, None, false, 16);

    assert!(result.is_ok(), "Should succeed with label only");
    assert_eq!(result.unwrap().len(), 16);
}

/// Test KBKDF with only context (no label) - should succeed.
#[test]
fn test_kbkdf_context_only() {
    let key = create_key(0xAA, 32);
    let context = Some(b"test_context".to_vec());

    let result = derive_and_extract(HashAlgo::sha256(), &key, None, context, false, 16);

    assert!(result.is_ok(), "Should succeed with context only");
    assert_eq!(result.unwrap().len(), 16);
}

/// Test KBKDF with very large output length.
///
/// Validates that KBKDF can derive multiple rounds (e.g., 1000 bytes = 32 rounds for SHA-256).
#[test]
fn test_kbkdf_large_output() {
    let key = create_key(0x22, 32);
    let label = Some(b"large_output".to_vec());
    let output_len = 1000;

    let result = derive_and_extract(HashAlgo::sha256(), &key, label, None, false, output_len);

    assert!(result.is_ok(), "Should succeed with large output");
    assert_eq!(result.unwrap().len(), output_len);
}

/// Test KBKDF with minimal output length (1 byte).
#[test]
fn test_kbkdf_minimal_output() {
    let key = create_key(0x10, 32);
    let label = Some(b"minimal".to_vec());

    let result = derive_and_extract(HashAlgo::sha256(), &key, label, None, false, 1);

    assert!(result.is_ok(), "Should succeed with 1 byte output");
    assert_eq!(result.unwrap().len(), 1);
}

/// Test KBKDF with different hash algorithms produce different outputs.
#[test]
fn test_kbkdf_different_hash_algos() {
    let key = create_key(0x33, 32);
    let label = Some(b"hash_test".to_vec());
    let output_len = 32;

    // Derive with SHA-256
    let bytes_sha256 = derive_and_extract(
        HashAlgo::sha256(),
        &key,
        label.clone(),
        None,
        false,
        output_len,
    )
    .expect("SHA-256 failed");

    // Derive with SHA-384
    let bytes_sha384 = derive_and_extract(HashAlgo::sha384(), &key, label, None, false, output_len)
        .expect("SHA-384 failed");

    // Outputs should be different
    assert_ne!(
        bytes_sha256, bytes_sha384,
        "Different hash algorithms should produce different outputs"
    );
}

/// Test KBKDF with use_length parameter variations.
#[test]
fn test_kbkdf_use_length_variations() {
    let key = create_key(0xFF, 32);
    let label = Some(b"length_test".to_vec());
    let output_len = 32;

    // Derive with use_length = false
    let bytes_no_len = derive_and_extract(
        HashAlgo::sha256(),
        &key,
        label.clone(),
        None,
        false,
        output_len,
    )
    .expect("No length failed");

    // Derive with use_length = true
    let bytes_with_len =
        derive_and_extract(HashAlgo::sha256(), &key, label, None, true, output_len)
            .expect("With length failed");

    // Outputs should be different due to different PRF inputs
    assert_ne!(
        bytes_no_len, bytes_with_len,
        "use_length parameter should affect output"
    );
}

/// Test KBKDF determinism - same inputs produce same outputs.
#[test]
fn test_kbkdf_determinism() {
    let key = create_key(0x42, 32);
    let label = Some(b"determinism".to_vec());
    let context = Some(b"test".to_vec());
    let output_len = 64;

    // First derivation
    let bytes1 = derive_and_extract(
        HashAlgo::sha256(),
        &key,
        label.clone(),
        context.clone(),
        false,
        output_len,
    )
    .expect("First derivation failed");

    // Second derivation with identical parameters
    let bytes2 = derive_and_extract(HashAlgo::sha256(), &key, label, context, false, output_len)
        .expect("Second derivation failed");

    // Outputs must be identical
    assert_eq!(
        bytes1, bytes2,
        "Same inputs should produce identical outputs"
    );
}
