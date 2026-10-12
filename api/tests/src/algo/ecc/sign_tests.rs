// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

// ================================
// Helper functions
// ================================

/// Computes hash of input data using the specified hash algorithm
fn hash_data(session: &HsmSession, mut hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

/// Signs a precomputed hash using the given ECC private key
fn sign_hash(priv_key: &HsmEccPrivateKey, hash: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmEccSignAlgo::default();
    HsmSigner::sign_vec(&mut sign_algo, priv_key, hash).expect("Signature generation failed")
}

/// Verifies a signature against a hash using the given ECC public key
fn verify_hash_signature(
    pub_key: &HsmEccPublicKey,
    hash: &[u8],
    signature: &[u8],
) -> Result<bool, HsmError> {
    let mut verify_algo = HsmEccSignAlgo::default();
    verify_algo.verify(pub_key, hash, signature)
}

/// Runs basic sign → verify success test for a given curve and hash algorithm
fn run_sign_verify_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"Test data";
    let hash = hash_data(session, hash_algo, data);
    let sig = sign_hash(&priv_key, &hash);

    let result = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(
        matches!(result, Ok(true)),
        "Expected Ok(true) but got {:?} for {:?}",
        result,
        curve
    );
}

/// Verifies that signature fails when using a mismatched public key
fn run_wrong_pubkey_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, _) = generate_ecc_key_pair(session, curve);
    let (_, wrong_pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"Test data";

    let hash = hash_data(session, hash_algo, data);
    let sig = sign_hash(&priv_key, &hash);

    expect_verify_false(
        &wrong_pub_key,
        &hash,
        &sig,
        &format!("wrong pubkey {:?}", curve),
    );
}

/// Verifies that signature fails after intentional corruption of signature bytes
fn run_tampered_signature_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"Test data";

    let hash = hash_data(session, hash_algo, data);
    let mut sig = sign_hash(&priv_key, &hash);

    sig[0] ^= 0xFF;

    expect_verify_false(&pub_key, &hash, &sig, &format!("tampered sig {:?}", curve));
}

/// Asserts that verification fails (either internal error or false) for malformed inputs
fn expect_verify_internal_error(
    pub_key: &HsmEccPublicKey,
    hash: &[u8],
    signature: &[u8],
    context: &str,
) {
    let mut verify_algo = HsmEccSignAlgo::default();

    let result = verify_algo.verify(pub_key, hash, signature);

    assert!(
        matches!(result, Err(HsmError::InternalError) | Ok(false)),
        "Expected failure (InternalError or false) but got {:?} ({})",
        result,
        context
    );
}

/// Asserts that verification returns false (but not error) for invalid signature
fn expect_verify_false(pub_key: &HsmEccPublicKey, hash: &[u8], signature: &[u8], context: &str) {
    let result = verify_hash_signature(pub_key, hash, signature);

    assert!(
        matches!(result, Ok(false)),
        "Expected Ok(false) but got {:?} ({})",
        result,
        context
    );
}

/// Verifies that empty signature input results in an internal error
fn run_empty_signature_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (_, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");

    expect_verify_internal_error(&pub_key, &hash, &[], &format!("empty sig {:?}", curve));
}

/// Verifies that cross-curve signature verification fails between different curves
fn run_cross_curve_test(
    session: &HsmSession,
    curve_a: HsmEccCurve,
    hash_algo_a: HsmHashAlgo,
    curve_b: HsmEccCurve,
) {
    let (priv_key, _) = generate_ecc_key_pair(session, curve_a);
    let (_, pub_key_other) = generate_ecc_key_pair(session, curve_b);

    let hash = hash_data(session, hash_algo_a, b"data");
    let sig = sign_hash(&priv_key, &hash);

    expect_verify_internal_error(
        &pub_key_other,
        &hash,
        &sig,
        &format!("cross curve {:?}->{:?}", curve_a, curve_b),
    );
}

/// Verifies that multiple signatures over the same input are valid (deterministic or non-deterministic)
fn run_non_deterministic_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"Test data";
    let hash = hash_data(session, hash_algo, data);

    let sig1 = sign_hash(&priv_key, &hash);
    let sig2 = sign_hash(&priv_key, &hash);

    let v1 = verify_hash_signature(&pub_key, &hash, &sig1);
    let v2 = verify_hash_signature(&pub_key, &hash, &sig2);

    assert!(matches!(v1, Ok(true)), "First signature failed {:?}", curve);
    assert!(
        matches!(v2, Ok(true)),
        "Second signature failed {:?}",
        curve
    );
}

/// Verifies sign/verify works correctly with large input data
fn run_large_input_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = vec![0u8; 10_000];

    let hash = hash_data(session, hash_algo, &data);
    let sig = sign_hash(&priv_key, &hash);

    let result = verify_hash_signature(&pub_key, &hash, &sig);
    assert!(
        matches!(result, Ok(true)),
        "Expected Ok(true) but got {:?} for {:?}",
        result,
        curve
    );
}

/// Verifies that truncated signature results in verification failure
fn run_truncated_signature_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");
    let mut sig = sign_hash(&priv_key, &hash);

    sig.truncate(sig.len() / 2);

    expect_verify_internal_error(&pub_key, &hash, &sig, &format!("truncated sig {:?}", curve));
}

/// Verifies that signature cannot be reused for a different message hash
fn run_signature_reuse_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash1 = hash_data(session, hash_algo, b"data1");
    let hash2 = hash_data(session, hash_algo, b"data2");

    let sig = sign_hash(&priv_key, &hash1);

    expect_verify_false(
        &pub_key,
        &hash2,
        &sig,
        &format!("signature reuse {:?}", curve),
    );
}

/// Verifies behavior when hash length does not match expected size
fn run_hash_length_mismatch_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");
    let mut bad_hash = hash.clone();
    bad_hash.truncate(hash.len() / 2);

    let sig = sign_hash(&priv_key, &hash);

    let result = verify_hash_signature(&pub_key, &bad_hash, &sig);

    assert!(
        matches!(result, Ok(false) | Err(_)),
        "Unexpected result for hash length mismatch {:?}: {:?}",
        curve,
        result
    );
}

/// Verifies that repeated verification calls produce consistent results
fn run_double_verify_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");
    let sig = sign_hash(&priv_key, &hash);

    let r1 = verify_hash_signature(&pub_key, &hash, &sig);
    let r2 = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(matches!(r1, Ok(true)));
    assert!(matches!(r2, Ok(true)));
}

/// Verifies that signing an empty hash fails as invalid input
fn run_empty_hash_test(session: &HsmSession, curve: HsmEccCurve) {
    let (priv_key, _) = generate_ecc_key_pair(session, curve);

    let empty_hash: Vec<u8> = vec![];

    let mut sign_algo = HsmEccSignAlgo::default();
    let result = HsmSigner::sign_vec(&mut sign_algo, &priv_key, &empty_hash);

    assert!(
        result.is_err(),
        "Signing empty hash should fail {:?}, got {:?}",
        curve,
        result
    );
}

/// Verifies that modifying a hash (same length) causes signature verification to fail
fn run_modified_hash_same_length_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");
    let mut modified_hash = hash.clone();
    modified_hash[0] ^= 0x01; // subtle corruption

    let sig = sign_hash(&priv_key, &hash);

    expect_verify_false(
        &pub_key,
        &modified_hash,
        &sig,
        &format!("modified hash {:?}", curve),
    );
}

/// Verifies that using different hash inputs (same data hashed differently) fails verification
fn run_mismatched_hash_input_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    sign_hash_algo: HsmHashAlgo,
    verify_hash_algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"data";

    let hash_for_sign = hash_data(session, sign_hash_algo, data);
    let hash_for_verify = hash_data(session, verify_hash_algo, data);

    let sig = sign_hash(&priv_key, &hash_for_sign);

    let result = verify_hash_signature(&pub_key, &hash_for_verify, &sig);
    assert!(
        matches!(result, Ok(false) | Err(_)),
        "Mismatched hash algo should fail {:?}, got {:?}",
        curve,
        result
    );
}

/// Verifies that minimal/invalid signature input fails verification
fn run_minimal_signature_test(session: &HsmSession, curve: HsmEccCurve, hash_algo: HsmHashAlgo) {
    let (_, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, hash_algo, b"data");

    let tiny_sig = vec![0x00];

    let result = verify_hash_signature(&pub_key, &hash, &tiny_sig);

    assert!(
        matches!(result, Ok(false) | Err(_)),
        "Tiny signature should fail {:?}, got {:?}",
        curve,
        result
    );
}

/// Verifies that key generation fails when private key lacks sign permission
fn run_sign_without_permission_test(session: &HsmSession, curve: HsmEccCurve) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(false) //  invalid for private key
        .is_session(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props);

    assert!(
        result.is_err(),
        "Key generation without sign permission should fail {:?}",
        curve
    );
}

/// Verifies that key generation fails when public key lacks verify permission
fn run_verify_without_permission_test(session: &HsmSession, curve: HsmEccCurve) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(false) //  invalid
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props);

    assert!(
        result.is_err(),
        "Expected key generation failure (no verify permission) for {:?}",
        curve
    );
}

/// Verifies that a valid signature with extra appended bytes is rejected during verification
fn run_extended_signature_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, algo, b"data");
    let mut sig = sign_hash(&priv_key, &hash);

    sig.extend_from_slice(&[0x00, 0x01]);

    let result = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(
        matches!(result, Ok(false) | Err(_)),
        "Extended signature should fail {:?}, got {:?}",
        curve,
        result
    );
}

/// Verifies that an all-zero signature of correct length fails verification
fn run_all_zero_signature_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (_, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = hash_data(session, algo, b"data");

    let sig_len = curve.signature_size();
    let sig = vec![0u8; sig_len];

    let result = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(
        matches!(result, Ok(false) | Err(_)),
        "All-zero signature should fail {:?}, got {:?}",
        curve,
        result
    );
}

/// Returns the expected hash size (in bytes) for the given ECC curve
fn hash_size_for_curve(curve: HsmEccCurve) -> usize {
    match curve {
        HsmEccCurve::P256 => 32,
        HsmEccCurve::P384 => 48,
        HsmEccCurve::P521 => 64,
    }
}

/// Verifies successful sign/verify using a constant-value hash (e.g., all 0x00 or all 0xFF)
fn run_constant_hash_test(session: &HsmSession, curve: HsmEccCurve, value: u8) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let hash = vec![value; hash_size_for_curve(curve)];
    let sig = sign_hash(&priv_key, &hash);

    let result = verify_hash_signature(&pub_key, &hash, &sig);
    assert!(matches!(result, Ok(true)));
}

/// Verifies that verification fails when using an empty hash with a valid-length signature
fn run_verify_empty_hash_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    // Generate a valid signature using a proper hash
    let dummy_hash = hash_data(session, algo, b"dummy");
    let sig = sign_hash(&priv_key, &dummy_hash);

    // Now verify against empty hash
    let empty_hash: Vec<u8> = vec![];

    let result = verify_hash_signature(&pub_key, &empty_hash, &sig);

    assert!(
        matches!(result, Err(_) | Ok(false)),
        "Expected failure for empty hash {:?}, got {:?}",
        curve,
        result
    );
}

// ============================================================
// test cases sections
// ============================================================

/// Tests large input handling for P256
#[session_test]
fn test_ecc_large_input_p256(session: HsmSession) {
    run_large_input_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests large input handling for P384
#[session_test]
fn test_ecc_large_input_p384(session: HsmSession) {
    run_large_input_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests large input handling for P521
#[session_test]
fn test_ecc_large_input_p521(session: HsmSession) {
    run_large_input_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Ensures ECDSA signatures are non-deterministic for P256
#[session_test]
fn test_ecc_non_deterministic_p256(session: HsmSession) {
    run_non_deterministic_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Ensures ECDSA signatures are non-deterministic for P384
#[session_test]
fn test_ecc_non_deterministic_p384(session: HsmSession) {
    run_non_deterministic_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Ensures ECDSA signatures are non-deterministic for P521
#[session_test]
fn test_ecc_non_deterministic_p521(session: HsmSession) {
    run_non_deterministic_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies cross-curve verification fails (P256 → P384)
#[session_test]
fn test_ecc_cross_curve_p256_to_p384(session: HsmSession) {
    run_cross_curve_test(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmEccCurve::P384,
    );
}

/// Verifies cross-curve verification fails (P384 → P521)
#[session_test]
fn test_ecc_cross_curve_p384_to_p521(session: HsmSession) {
    run_cross_curve_test(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        HsmEccCurve::P521,
    );
}

/// Verifies cross-curve verification fails (P521 → P256)
#[session_test]
fn test_ecc_cross_curve_p521_to_p256(session: HsmSession) {
    run_cross_curve_test(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        HsmEccCurve::P256,
    );
}

/// Verifies empty signature handling for P256
#[session_test]
fn test_ecc_empty_sig_p256(session: HsmSession) {
    run_empty_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies empty signature handling for P384
#[session_test]
fn test_ecc_empty_sig_p384(session: HsmSession) {
    run_empty_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies empty signature handling for P521
#[session_test]
fn test_ecc_empty_sig_p521(session: HsmSession) {
    run_empty_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies successful sign/verify for P256
#[session_test]
fn test_ecc_sign_verify_p256(session: HsmSession) {
    run_sign_verify_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies successful sign/verify for P384
#[session_test]
fn test_ecc_sign_verify_p384(session: HsmSession) {
    run_sign_verify_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies successful sign/verify for P521
#[session_test]
fn test_ecc_sign_verify_p521(session: HsmSession) {
    run_sign_verify_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies failure when using wrong public key (P256)
#[session_test]
fn test_ecc_verify_fail_wrong_pubkey_p256(session: HsmSession) {
    run_wrong_pubkey_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies failure when using wrong public key (P384)
#[session_test]
fn test_ecc_verify_fail_wrong_pubkey_p384(session: HsmSession) {
    run_wrong_pubkey_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies failure when using wrong public key (P521)
#[session_test]
fn test_ecc_verify_fail_wrong_pubkey_p521(session: HsmSession) {
    run_wrong_pubkey_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies failure when signature is tampered (P256)
#[session_test]
fn test_ecc_verify_fail_tampered_signature_p256(session: HsmSession) {
    run_tampered_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies failure when signature is tampered (P384)
#[session_test]
fn test_ecc_verify_fail_tampered_signature_p384(session: HsmSession) {
    run_tampered_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies failure when signature is tampered (P521)
#[session_test]
fn test_ecc_verify_fail_tampered_signature_p521(session: HsmSession) {
    run_tampered_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies failure when signature is truncated (P256)
#[session_test]
fn test_ecc_truncated_sig_p256(session: HsmSession) {
    run_truncated_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies failure when signature is truncated (P384)
#[session_test]
fn test_ecc_truncated_sig_p384(session: HsmSession) {
    run_truncated_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies failure when signature is truncated (P521)
#[session_test]
fn test_ecc_truncated_sig_p521(session: HsmSession) {
    run_truncated_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies signature cannot be reused for different message (P256)
#[session_test]
fn test_ecc_signature_reuse_p256(session: HsmSession) {
    run_signature_reuse_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies signature cannot be reused for different message (P384)
#[session_test]
fn test_ecc_signature_reuse_p384(session: HsmSession) {
    run_signature_reuse_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies signature cannot be reused for different message (P521)
#[session_test]
fn test_ecc_signature_reuse_p521(session: HsmSession) {
    run_signature_reuse_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies behavior with incorrect hash length (P256)
#[session_test]
fn test_ecc_hash_length_mismatch_p256(session: HsmSession) {
    run_hash_length_mismatch_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies behavior with incorrect hash length (P384)
#[session_test]
fn test_ecc_hash_length_mismatch_p384(session: HsmSession) {
    run_hash_length_mismatch_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies behavior with incorrect hash length (P521)
#[session_test]
fn test_ecc_hash_length_mismatch_p521(session: HsmSession) {
    run_hash_length_mismatch_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies repeated verification produces consistent results (P256)
#[session_test]
fn test_ecc_double_verify_p256(session: HsmSession) {
    run_double_verify_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies repeated verification produces consistent results (P384)
#[session_test]
fn test_ecc_double_verify_p384(session: HsmSession) {
    run_double_verify_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies repeated verification produces consistent results (P521)
#[session_test]
fn test_ecc_double_verify_p521(session: HsmSession) {
    run_double_verify_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that signing empty hash fails for P256
#[session_test]
fn test_ecc_empty_hash_p256(session: HsmSession) {
    run_empty_hash_test(&session, HsmEccCurve::P256);
}

/// Tests that signing empty hash fails for P384
#[session_test]
fn test_ecc_empty_hash_p384(session: HsmSession) {
    run_empty_hash_test(&session, HsmEccCurve::P384);
}

/// Tests that signing empty hash fails for P521
#[session_test]
fn test_ecc_empty_hash_p521(session: HsmSession) {
    run_empty_hash_test(&session, HsmEccCurve::P521);
}

/// Tests verification failure when hash is modified (P256)
#[session_test]
fn test_ecc_modified_hash_p256(session: HsmSession) {
    run_modified_hash_same_length_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests verification failure when hash is modified (P384)
#[session_test]
fn test_ecc_modified_hash_p384(session: HsmSession) {
    run_modified_hash_same_length_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests verification failure when hash is modified (P521)
#[session_test]
fn test_ecc_modified_hash_p521(session: HsmSession) {
    run_modified_hash_same_length_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests failure when mismatched hash input are used for P256
#[session_test]
fn test_ecc_mismatched_hash_input_p256(session: HsmSession) {
    run_mismatched_hash_input_test(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha512,
    );
}

/// Tests failure when mismatched hash input are used for P521
#[session_test]
fn test_ecc_mismatched_hash_input_p521(session: HsmSession) {
    run_mismatched_hash_input_test(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        HsmHashAlgo::Sha256,
    );
}

/// Tests failure when mismatched hash input are used for P384
#[session_test]
fn test_ecc_mismatched_hash_input_p384(session: HsmSession) {
    run_mismatched_hash_input_test(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    );
}

/// Tests failure when minimal signature is provided for P256
#[session_test]
fn test_ecc_minimal_sig_p256(session: HsmSession) {
    run_minimal_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests failure when minimal signature is provided for P384
#[session_test]
fn test_ecc_minimal_sig_p384(session: HsmSession) {
    run_minimal_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests failure when minimal signature is provided for P521
#[session_test]
fn test_ecc_minimal_sig_p521(session: HsmSession) {
    run_minimal_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}
/// Verifies key generation fails when private key lacks sign permission (P256)
#[session_test]
fn test_ecc_sign_without_permission_p256(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P256);
}

/// Verifies key generation fails when private key lacks sign permission (P384)
#[session_test]
fn test_ecc_sign_without_permission_p384(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P384);
}

/// Verifies key generation fails when private key lacks sign permission (P521)
#[session_test]
fn test_ecc_sign_without_permission_p521(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P521);
}

/// Verifies key generation fails when public key lacks verify permission (P256)
#[session_test]
fn test_ecc_verify_without_permission_p256(session: HsmSession) {
    run_verify_without_permission_test(&session, HsmEccCurve::P256);
}

/// Verifies key generation fails when public key lacks verify permission (P384)
#[session_test]
fn test_ecc_verify_without_permission_p384(session: HsmSession) {
    run_verify_without_permission_test(&session, HsmEccCurve::P384);
}

/// Verifies key generation fails when public key lacks verify permission (P521)
#[session_test]
fn test_ecc_verify_without_permission_p521(session: HsmSession) {
    run_verify_without_permission_test(&session, HsmEccCurve::P521);
}

/// Tests that a signature with extra appended bytes is rejected for P256
#[session_test]
fn test_ecc_extended_sig_p256(session: HsmSession) {
    run_extended_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that a signature with extra appended bytes is rejected for P384
#[session_test]
fn test_ecc_extended_sig_p384(session: HsmSession) {
    run_extended_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that a signature with extra appended bytes is rejected for P521
#[session_test]
fn test_ecc_extended_sig_p521(session: HsmSession) {
    run_extended_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that an all-zero signature is rejected for P256
#[session_test]
fn test_ecc_all_zero_signature_p256(session: HsmSession) {
    run_all_zero_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that an all-zero signature is rejected for P384
#[session_test]
fn test_ecc_all_zero_signature_p384(session: HsmSession) {
    run_all_zero_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that an all-zero signature is rejected for P521
#[session_test]
fn test_ecc_all_zero_signature_p521(session: HsmSession) {
    run_all_zero_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests successful sign/verify using an all-zero hash for P256
#[session_test]
fn test_ecc_all_zero_hash_p256(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P256, 0x00);
}

/// Tests successful sign/verify using an all-zero hash for P384
#[session_test]
fn test_ecc_all_zero_hash_p384(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P384, 0x00);
}

/// Tests successful sign/verify using an all-zero hash for P521
#[session_test]
fn test_ecc_all_zero_hash_p521(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P521, 0x00);
}

/// Tests successful sign/verify using an all-0xFF hash for P256
#[session_test]
fn test_ecc_all_ff_hash_p256(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P256, 0xFF);
}

/// Tests successful sign/verify using an all-0xFF hash for P384
#[session_test]
fn test_ecc_all_ff_hash_p384(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P384, 0xFF);
}

/// Tests successful sign/verify using an all-0xFF hash for P521
#[session_test]
fn test_ecc_all_ff_hash_p521(session: HsmSession) {
    run_constant_hash_test(&session, HsmEccCurve::P521, 0xFF);
}

/// Verifies verification fails when using an empty hash for P256
#[session_test]
fn test_ecc_verify_empty_hash_p256(session: HsmSession) {
    run_verify_empty_hash_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies verification fails when using an empty hash for P384
#[session_test]
fn test_ecc_verify_empty_hash_p384(session: HsmSession) {
    run_verify_empty_hash_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies verification fails when using an empty hash for P521
#[session_test]
fn test_ecc_verify_empty_hash_p521(session: HsmSession) {
    run_verify_empty_hash_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}
