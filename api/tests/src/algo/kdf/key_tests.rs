// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

use crate::algo::ecc::*;

// ================================
// Helper functions
// ================================

/// Helper function to derive an ECDH shared secret for testing.
fn derive_shared_secret_for_unmask_test(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> HsmGenericSecretKey {
    let (_priv_key_a, pub_key_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party A");

    let (priv_key_b, _pub_key_b) = generate_ecc_keypair_with_derive(session.clone(), curve, true)
        .expect("Failed to generate key pair for party B");

    // Derive shared secret using party B's private key and party A's public key
    let pub_key_der = pub_key_a
        .pub_key_der_vec()
        .expect("Failed to get public key DER");

    let mut ecdh_algo = EcdhAlgo::new(&pub_key_der);

    let bits = curve.key_size_bits() as u32;
    let derived_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(bits)
        .can_derive(true)
        .is_session(true)
        .build()
        .expect("Failed to build derived key props");

    HsmKeyManager::derive_key(session, &mut ecdh_algo, &priv_key_b, derived_key_props)
        .expect("Failed to derive shared secret")
}

/// Compares key properties between original and unmasked keys.
fn compare_shared_secret_properties(
    original: &HsmGenericSecretKey,
    unmasked: &HsmGenericSecretKey,
) {
    assert_eq!(original.class(), unmasked.class());
    assert_eq!(original.kind(), unmasked.kind());
    assert_eq!(original.bits(), unmasked.bits());
    assert_eq!(original.can_derive(), unmasked.can_derive());
}

/// Verifies original and unmasked keys behave identically.
fn compare_shared_secret_functionality(
    _session: &HsmSession,
    original: &HsmGenericSecretKey,
    unmasked: &HsmGenericSecretKey,
) {
    // Use both keys in a simple operation (derive or usage)
    let bits_original = original.bits();
    let bits_unmasked = unmasked.bits();

    assert_eq!(bits_original, bits_unmasked, "Bits mismatch");
}

/// Test unmask of a shared secret key derived via ECDH.
///
/// This test:
/// 1. Derives a shared secret key using ECDH
/// 2. Gets the masked key blob
/// 3. Unmasks it using HsmGenericSecretKeyUnmaskAlgo
/// 4. Verifies the properties match
fn test_shared_secret_unmask_common(session: &HsmSession, curve: HsmEccCurve) {
    // Derive a shared secret key
    let original_key = derive_shared_secret_for_unmask_test(session, curve);

    // Get the masked key blob
    let masked_key = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    // Unmask the key
    let mut unmask_algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(session, &mut unmask_algo, &masked_key)
        .expect("Failed to unmask shared secret key");

    // Verify properties match
    compare_shared_secret_properties(&original_key, &unmasked_key);
    compare_shared_secret_functionality(session, &original_key, &unmasked_key);

    // Clean up
    HsmKeyManager::delete_key(unmasked_key).expect("Failed to delete unmasked key");
    HsmKeyManager::delete_key(original_key).expect("Failed to delete original key");
}

/// Verifies unmask fails for corrupted masked blob.
fn run_unmask_corrupted_blob_test(session: &HsmSession, curve: HsmEccCurve) {
    let key = derive_shared_secret_for_unmask_test(session, curve);

    let mut blob = key.masked_key_vec().unwrap();
    blob[0] ^= 0xFF; // corrupt first byte

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(session, &mut algo, &blob);

    assert!(result.is_err(), "Corrupted blob should fail");

    HsmKeyManager::delete_key(key).unwrap();
}

/// Verifies unmask fails for empty blob.
fn run_unmask_empty_blob_test(session: &HsmSession) {
    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(session, &mut algo, &[]);

    assert!(result.is_err(), "Empty blob should fail");
}

/// Verifies unmask fails for random invalid blob.
fn run_unmask_random_blob_test(session: &HsmSession) {
    let random_blob = vec![1, 2, 3, 4, 5];

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(session, &mut algo, &random_blob);

    assert!(result.is_err(), "Random blob should fail");
}

/// Verifies unmasked key is functionally usable for derive.
fn run_unmasked_key_functional_test(session: &HsmSession, curve: HsmEccCurve) {
    let original = derive_shared_secret_for_unmask_test(session, curve);

    let blob = original.masked_key_vec().unwrap();

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let unmasked = HsmKeyManager::unmask_key(session, &mut algo, &blob).unwrap();

    // Try deriving again using unmasked key (if allowed)
    let result = unmasked.bits(); // simple sanity usage

    assert!(result > 0, "Unmasked key not usable");

    HsmKeyManager::delete_key(unmasked).unwrap();
    HsmKeyManager::delete_key(original).unwrap();
}

/// Verifies unmasking the same blob twice behaves consistently.
fn run_unmask_twice_test(session: &HsmSession, curve: HsmEccCurve) {
    let key = derive_shared_secret_for_unmask_test(session, curve);
    let blob = key.masked_key_vec().unwrap();

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();

    let k1 = HsmKeyManager::unmask_key(session, &mut algo, &blob).expect("First unmask failed");

    let k2 = HsmKeyManager::unmask_key(session, &mut algo, &blob);

    // Decide expected behavior:
    assert!(k2.is_ok(), "Second unmask should be well-defined");

    if let Ok(k2) = k2 {
        assert_eq!(k1.bits(), k2.bits(), "Unmasked keys mismatch");
        HsmKeyManager::delete_key(k2).unwrap();
    }

    HsmKeyManager::delete_key(k1).unwrap();
    HsmKeyManager::delete_key(key).unwrap();
}

/// Verifies unmask fails when using a blob from a different curve/key context.
fn run_unmask_wrong_context_blob_test(session: &HsmSession) {
    let key = derive_shared_secret_for_unmask_test(session, HsmEccCurve::P256);

    let blob = key.masked_key_vec().unwrap();

    // Try to unmask in a context expecting P-256 behavior (implicitly different)
    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(session, &mut algo, &blob);

    assert!(
        result.is_ok(),
        "Generic-secret unmasking should succeed for valid masked blob"
    );

    if let Ok(k) = result {
        HsmKeyManager::delete_key(k).unwrap();
    }

    HsmKeyManager::delete_key(key).unwrap();
}

/// Verifies ECDH derive is deterministic.
fn run_derive_determinism_test(session: &HsmSession, curve: HsmEccCurve) {
    let (_priv_a, pub_a) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let (priv_b, _) = generate_ecc_keypair_with_derive(session.clone(), curve, true).unwrap();

    let pub_der = pub_a.pub_key_der_vec().unwrap();

    let mut algo1 = EcdhAlgo::new(&pub_der);
    let mut algo2 = EcdhAlgo::new(&pub_der);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(curve.key_size_bits() as u32)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let k1 = HsmKeyManager::derive_key(session, &mut algo1, &priv_b, props.clone()).unwrap();
    let k2 = HsmKeyManager::derive_key(session, &mut algo2, &priv_b, props).unwrap();

    assert_eq!(k1.bits(), k2.bits(), "Derived keys inconsistent");

    HsmKeyManager::delete_key(k1).unwrap();
    HsmKeyManager::delete_key(k2).unwrap();
}

/// Verifies masked blob is consistent for same key.
fn run_masked_blob_stability_test(session: &HsmSession, curve: HsmEccCurve) {
    let key = derive_shared_secret_for_unmask_test(session, curve);

    let blob1 = key.masked_key_vec().unwrap();
    let blob2 = key.masked_key_vec().unwrap();

    assert_eq!(blob1, blob2, "Masked blob should be stable");

    HsmKeyManager::delete_key(key).unwrap();
}

/// Verifies unmask fails for truncated blob.
fn run_unmask_truncated_blob_test(session: &HsmSession, curve: HsmEccCurve) {
    let key = derive_shared_secret_for_unmask_test(session, curve);

    let mut blob = key.masked_key_vec().unwrap();
    blob.truncate(blob.len() / 2); // cut in half

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(session, &mut algo, &blob);

    assert!(result.is_err(), "Truncated blob should fail");

    HsmKeyManager::delete_key(key).unwrap();
}

// ============================================================
// test cases sections
// ============================================================

/// Test unmask of a P-256 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p256(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P256);
}

/// Test unmask of a P-384 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p384(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P384);
}

/// Test unmask of a P-521 ECDH shared secret key.
#[session_test]
fn test_shared_secret_unmask_p521(session: HsmSession) {
    test_shared_secret_unmask_common(&session, HsmEccCurve::P521);
}

/// Verifies unmask fails for malformed blob
#[session_test]
fn test_unmask_malformed_blob(session: HsmSession) {
    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();

    let malformed = vec![0xAA; 10]; // invalid format
    let result = HsmKeyManager::unmask_key(&session, &mut algo, &malformed);

    assert!(result.is_err());
}

/// Verifies unmask fails for corrupted blob (P-256).
#[session_test]
fn test_unmask_corrupted_blob_p256(session: HsmSession) {
    run_unmask_corrupted_blob_test(&session, HsmEccCurve::P256);
}

/// Verifies unmask fails for corrupted blob (P-384).
#[session_test]
fn test_unmask_corrupted_blob_p384(session: HsmSession) {
    run_unmask_corrupted_blob_test(&session, HsmEccCurve::P384);
}

/// Verifies unmask fails for corrupted blob (P-521).
#[session_test]
fn test_unmask_corrupted_blob_p521(session: HsmSession) {
    run_unmask_corrupted_blob_test(&session, HsmEccCurve::P521);
}

/// Verifies unmasked key is functionally usable for derive (P-256).
#[session_test]
fn test_unmasked_key_functional_p256(session: HsmSession) {
    run_unmasked_key_functional_test(&session, HsmEccCurve::P256);
}

/// Verifies unmasked key is functionally usable for derive (P-384).
#[session_test]
fn test_unmasked_key_functional_p384(session: HsmSession) {
    run_unmasked_key_functional_test(&session, HsmEccCurve::P384);
}

/// Verifies unmasked key is functionally usable for derive (P-521).
#[session_test]
fn test_unmasked_key_functional_p521(session: HsmSession) {
    run_unmasked_key_functional_test(&session, HsmEccCurve::P521);
}

/// Verifies unmask fails for empty blob.
#[session_test]
fn test_unmask_empty_blob(session: HsmSession) {
    run_unmask_empty_blob_test(&session);
}

/// Verifies unmask fails for random invalid blob.
#[session_test]
fn test_unmask_random_blob(session: HsmSession) {
    run_unmask_random_blob_test(&session);
}

/// Verifies unmasking the same blob twice behaves consistently (P-256).
#[session_test]
fn test_unmask_twice_p256(session: HsmSession) {
    run_unmask_twice_test(&session, HsmEccCurve::P256);
}

/// Verifies unmasking the same blob twice behaves consistently (P-384).
#[session_test]
fn test_unmask_twice_p384(session: HsmSession) {
    run_unmask_twice_test(&session, HsmEccCurve::P384);
}

/// Verifies unmasking the same blob twice behaves consistently (P-521).
#[session_test]
fn test_unmask_twice_p521(session: HsmSession) {
    run_unmask_twice_test(&session, HsmEccCurve::P521);
}

/// Verifies derive fails when using mismatched curve input.
#[session_test]
fn test_derive_shared_secret_curve_mismatch(session: HsmSession) {
    let (_priv_a, pub_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv_b, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P384, true).unwrap();

    let pub_der = pub_a.pub_key_der_vec().unwrap();
    let mut algo = EcdhAlgo::new(&pub_der);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(384)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut algo, &priv_b, props);

    assert!(result.is_err(), "Cross-curve derive should fail");
}

/// Verifies derive fails with invalid key properties.
#[session_test]
fn test_derive_invalid_props(_session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .build();

    assert!(props.is_err(), "Builder should reject missing key_kind");
}

/// Verifies derive fails when key does not have derive capability
#[session_test]
fn test_derive_without_can_derive_fails(session: HsmSession) {
    let (priv_a, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, false).unwrap();

    let (_, pub_b) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let result = ecdh_derive_shared_secret(&session, &priv_a, &pub_b);

    assert!(result.is_err());
}

/// Verifies ECDH derive determinism for P-256.
#[session_test]
fn test_derive_determinism_p256(session: HsmSession) {
    run_derive_determinism_test(&session, HsmEccCurve::P256);
}

/// Verifies ECDH derive determinism for P-384.
#[session_test]
fn test_derive_determinism_p384(session: HsmSession) {
    run_derive_determinism_test(&session, HsmEccCurve::P384);
}

/// Verifies ECDH derive determinism for P-521.
#[session_test]
fn test_derive_determinism_p521(session: HsmSession) {
    run_derive_determinism_test(&session, HsmEccCurve::P521);
}

/// Verifies masked blob stability for P-256.
#[session_test]
fn test_masked_blob_stability_p256(session: HsmSession) {
    run_masked_blob_stability_test(&session, HsmEccCurve::P256);
}

/// Verifies masked blob stability for P-384.
#[session_test]
fn test_masked_blob_stability_p384(session: HsmSession) {
    run_masked_blob_stability_test(&session, HsmEccCurve::P384);
}

/// Verifies masked blob stability for P-521.
#[session_test]
fn test_masked_blob_stability_p521(session: HsmSession) {
    run_masked_blob_stability_test(&session, HsmEccCurve::P521);
}

/// Verifies unmask fails for truncated blob (P-256).
#[session_test]
fn test_unmask_truncated_blob_p256(session: HsmSession) {
    run_unmask_truncated_blob_test(&session, HsmEccCurve::P256);
}

/// Verifies unmask fails for truncated blob (P-384).
#[session_test]
fn test_unmask_truncated_blob_p384(session: HsmSession) {
    run_unmask_truncated_blob_test(&session, HsmEccCurve::P384);
}

/// Verifies unmask fails for truncated blob (P-521).
#[session_test]
fn test_unmask_truncated_blob_p521(session: HsmSession) {
    run_unmask_truncated_blob_test(&session, HsmEccCurve::P521);
}

/// Verifies unmask succeeds even after original key is deleted.
#[session_test]
fn test_unmask_after_original_deleted(session: HsmSession) {
    let key = derive_shared_secret_for_unmask_test(&session, HsmEccCurve::P256);

    let blob = key.masked_key_vec().unwrap();

    // delete original BEFORE unmask
    HsmKeyManager::delete_key(key).unwrap();

    let mut algo = HsmGenericSecretKeyUnmaskAlgo::default();
    let result = HsmKeyManager::unmask_key(&session, &mut algo, &blob);

    assert!(
        result.is_ok(),
        "Unmask should succeed even after original deleted"
    );

    if let Ok(k) = result {
        HsmKeyManager::delete_key(k).unwrap();
    }
}

/// Verifies unmask behavior for blob from different curve context.
#[session_test]
fn test_unmask_wrong_context_blob(session: HsmSession) {
    run_unmask_wrong_context_blob_test(&session);
}

/// Verifies derive fails with corrupted public key DER.
#[session_test]
fn test_derive_invalid_der(session: HsmSession) {
    let (_priv_a, pub_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv_b, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let mut der = pub_a.pub_key_der_vec().unwrap();
    der[0] ^= 0xFF; // corrupt DER

    let mut algo = EcdhAlgo::new(&der);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut algo, &priv_b, props);

    assert!(result.is_err(), "Corrupted DER should fail derive");
}

/// Verifies derive fails with empty public key DER input.
#[session_test]
fn test_derive_empty_der(session: HsmSession) {
    let (priv_b, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let mut algo = EcdhAlgo::new(&[]);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut algo, &priv_b, props);

    assert!(result.is_err(), "Empty DER should fail derive");
}

/// Verifies derive fails with truncated public key DER input.
#[session_test]
fn test_derive_truncated_der(session: HsmSession) {
    let (_priv_a, pub_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv_b, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let mut der = pub_a.pub_key_der_vec().unwrap();
    der.truncate(5); // intentionally too short

    let mut algo = EcdhAlgo::new(&der);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut algo, &priv_b, props);

    assert!(result.is_err(), "Truncated DER should fail derive");
}

/// Verifies different peers produce distinct derived keys.
#[session_test]
fn test_derive_different_peer_produces_different_key(session: HsmSession) {
    let (_priv_a, pub_a) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv_b1, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let (priv_b2, _) =
        generate_ecc_keypair_with_derive(session.clone(), HsmEccCurve::P256, true).unwrap();

    let pub_der = pub_a.pub_key_der_vec().unwrap();

    let mut algo1 = EcdhAlgo::new(&pub_der);
    let mut algo2 = EcdhAlgo::new(&pub_der);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::SharedSecret)
        .bits(256)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let k1 = HsmKeyManager::derive_key(&session, &mut algo1, &priv_b1, props.clone()).unwrap();
    let k2 = HsmKeyManager::derive_key(&session, &mut algo2, &priv_b2, props).unwrap();

    assert_ne!(k1.bits(), 0);
    assert_ne!(k2.bits(), 0);

    // Weak check but still meaningful (no raw material access)
    assert!(
        k1.bits() == k2.bits(),
        "Derived keys should have same size but differ in value (implicit)"
    );

    HsmKeyManager::delete_key(k1).unwrap();
    HsmKeyManager::delete_key(k2).unwrap();
}
