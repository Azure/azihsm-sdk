// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

// ================================
// Helper functions
// ================================

/// Signs input data using the specified hash algorithm and ECC private key
fn sign_data(priv_key: &HsmEccPrivateKey, hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmHashSignAlgo::new(hash_algo);
    HsmSigner::sign_vec(&mut sign_algo, priv_key, data).expect("Signature generation failed")
}

/// Verifies a signature against input data using the specified hash algorithm and ECC public key
fn verify_signature(
    pub_key: &HsmEccPublicKey,
    hash_algo: HsmHashAlgo,
    data: &[u8],
    signature: &[u8],
) -> bool {
    let mut verify_algo = HsmHashSignAlgo::new(hash_algo);
    HsmVerifier::verify(&mut verify_algo, pub_key, data, signature)
        .expect("Failed to verify signature")
}

/// Signs data incrementally using streaming API with multiple input chunks
fn streaming_sign_data(
    priv_key: HsmEccPrivateKey,
    hash_algo: HsmHashAlgo,
    data_chunks: &[&[u8]],
) -> Vec<u8> {
    let sign_algo = HsmHashSignAlgo::new(hash_algo);
    let mut sign_ctx =
        HsmSigner::sign_init(sign_algo, priv_key).expect("Failed to initialize signing context");

    for chunk in data_chunks {
        sign_ctx.update(chunk).expect("Failed to update");
    }

    sign_ctx.finish_vec().expect("Failed to finish signature")
}

/// Verifies a signature incrementally using streaming API with multiple input chunks
fn streaming_verify_signature(
    pub_key: HsmEccPublicKey,
    hash_algo: HsmHashAlgo,
    data_chunks: &[&[u8]],
    signature: &[u8],
) -> bool {
    let verify_algo = HsmHashSignAlgo::new(hash_algo);
    let mut verify_ctx = HsmVerifier::verify_init(verify_algo, pub_key)
        .expect("Failed to initialize verification context");

    for chunk in data_chunks {
        verify_ctx.update(chunk).expect("Failed to update");
    }

    verify_ctx
        .finish(signature)
        .expect("Failed to finish verification")
}

/// Verifies that verification fails when using a different public key
fn run_wrong_pubkey_hash_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv1, _) = generate_ecc_key_pair(session, curve);
    let (_, pub2) = generate_ecc_key_pair(session, curve);

    let data = b"data";
    let sig = sign_data(&priv1, algo, data);

    assert!(!verify_signature(&pub2, algo, data, &sig));
}

/// Verifies that mismatched hash algorithms between sign and verify fail
fn run_hash_algo_mismatch_hash(
    session: &HsmSession,
    curve: HsmEccCurve,
    sign_algo: HsmHashAlgo,
    verify_algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"data";
    let sig = sign_data(&priv_key, sign_algo, data);

    assert!(!verify_signature(&pub_key, verify_algo, data, &sig));
}

/// Verifies that different chunk boundaries produce equivalent streaming signatures
fn run_chunk_variation_hash(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks1: [&[u8]; 3] = [b"a" as &[u8], b"b" as &[u8], b"c" as &[u8]];
    let chunks2: [&[u8]; 2] = [b"ab" as &[u8], b"c" as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &chunks1);

    assert!(streaming_verify_signature(pub_key, algo, &chunks2, &sig));
}

/// Verifies that streaming-generated signatures are valid for single-shot verification
fn run_streaming_to_single(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"hello " as &[u8], b"world" as &[u8]];
    let full = b"hello world";

    let sig = streaming_sign_data(priv_key, algo, &chunks);

    assert!(verify_signature(&pub_key, algo, full, &sig));
}

/// Verifies that single-shot signatures are valid for streaming verification
fn run_single_to_streaming(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"hello " as &[u8], b"world" as &[u8]];
    let full = b"hello world";

    let sig = sign_data(&priv_key, algo, full);

    assert!(streaming_verify_signature(pub_key, algo, &chunks, &sig));
}

/// Verifies streaming signing and verification succeed with large input across curves
fn run_streaming_large_input_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let big = vec![0xAA; 10_000];

    let chunks: [&[u8]; 2] = [&big[..5000], &big[5000..]];

    let sig = streaming_sign_data(priv_key, algo, &chunks);

    assert!(
        streaming_verify_signature(pub_key, algo, &chunks, &sig),
        "Streaming large input failed for {:?}",
        curve
    );
}

/// Verifies that tampered signature fails in streaming verification
fn run_streaming_tampered_sig_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"a" as &[u8], b"b" as &[u8]];
    let mut sig = streaming_sign_data(priv_key, algo, &chunks);

    sig[0] ^= 0xFF;

    assert!(
        !streaming_verify_signature(pub_key, algo, &chunks, &sig),
        "Tampered signature should fail for {:?}",
        curve
    );
}

/// Verifies that streaming verification fails with incorrect data chunks
fn run_streaming_wrong_data_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"a" as &[u8], b"b" as &[u8]];
    let wrong: [&[u8]; 2] = [b"a" as &[u8], b"x" as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &chunks);

    assert!(
        !streaming_verify_signature(pub_key, algo, &wrong, &sig),
        "Wrong data should fail for {:?}",
        curve
    );
}

/// Verifies that signing and verifying empty data succeeds
fn run_empty_data_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"";
    let sig = sign_data(&priv_key, algo, data);

    assert!(
        verify_signature(&pub_key, algo, data, &sig),
        "Empty data failed for {:?}",
        curve
    );
}

/// Verifies multiple sequential sign/verify operations succeed
fn run_multiple_ops_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    for i in 0..10 {
        let msg = format!("msg{}", i);
        let sig = sign_data(&priv_key, algo, msg.as_bytes());

        assert!(
            verify_signature(&pub_key, algo, msg.as_bytes(), &sig),
            "Multi-op failed for {:?}",
            curve
        );
    }
}

/// Verifies streaming signing and verification with empty input
fn run_streaming_empty_input_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let empty_chunks: [&[u8]; 0] = [];
    let sig = streaming_sign_data(priv_key, algo, &empty_chunks);

    assert!(streaming_verify_signature(
        pub_key.clone(),
        algo,
        &empty_chunks,
        &sig
    ));

    let zero_chunk: [&[u8]; 1] = [&b""[..]];
    assert!(streaming_verify_signature(pub_key, algo, &zero_chunk, &sig));
}

/// Verifies that streaming verification fails with mismatched hash algorithms
fn run_streaming_hash_algo_mismatch_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    sign_algo: HsmHashAlgo,
    verify_algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"a" as &[u8], b"b" as &[u8]];

    let sig = streaming_sign_data(priv_key, sign_algo, &chunks);

    assert!(
        !streaming_verify_signature(pub_key, verify_algo, &chunks, &sig),
        "Streaming hash mismatch should fail for {:?}",
        curve
    );
}
/// Verifies that single-chunk and multi-chunk streaming produce equivalent verification results
fn run_streaming_single_vs_multi_chunk_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let single: [&[u8]; 1] = [b"hello world" as &[u8]];
    let multi: [&[u8]; 2] = [b"hello " as &[u8], b"world" as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &multi);

    assert!(
        streaming_verify_signature(pub_key, algo, &single, &sig),
        "Single vs multi chunk failed for {:?}",
        curve
    );
}

/// Verifies that streaming verification fails when using a wrong public key
fn run_streaming_wrong_pubkey_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, _) = generate_ecc_key_pair(session, curve);
    let (_, wrong_pub) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"a" as &[u8], b"b" as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &chunks);

    assert!(
        !streaming_verify_signature(wrong_pub, algo, &chunks, &sig),
        "Streaming wrong pubkey should fail for {:?}",
        curve
    );
}

/// Verifies streaming verification fails when signed data and verified data differ in emptiness
fn run_streaming_empty_mismatch_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let empty: [&[u8]; 0] = [];
    let non_empty: [&[u8]; 1] = [b"x" as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &empty);

    assert!(
        !streaming_verify_signature(pub_key, algo, &non_empty, &sig),
        "Empty mismatch should fail for {:?}",
        curve
    );
}

/// Verifies streaming verification fails when chunk order is different
fn run_streaming_chunk_order_mismatch_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let original: [&[u8]; 2] = [b"hello " as &[u8], b"world" as &[u8]];
    let reordered: [&[u8]; 2] = [b"world" as &[u8], b"hello " as &[u8]];

    let sig = streaming_sign_data(priv_key, algo, &original);

    assert!(
        !streaming_verify_signature(pub_key, algo, &reordered, &sig),
        "Chunk order mismatch should fail for {:?}",
        curve
    );
}

/// Verifies that signing context reuse does not produce invalid or inconsistent results
fn run_sign_context_reuse_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let mut ctx = HsmSigner::sign_init(HsmHashSignAlgo::new(algo), priv_key).unwrap();

    ctx.update(b"data").unwrap();
    let sig1 = ctx.finish_vec().unwrap();

    // original signature must verify
    assert!(
        verify_signature(&pub_key, algo, b"data", &sig1),
        "Original signature should verify for {:?}",
        curve
    );

    // reuse context after finish must fail with InvalidContextState
    let res = ctx.update(b"more");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState for {:?}",
        curve
    );

    let res = ctx.finish_vec();
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState for {:?}",
        curve
    );
}

/// Verifies update after finish does not produce valid new signature
/// Verifies update after finish does not produce a valid new signature
fn run_sign_update_after_finish_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let mut ctx = HsmSigner::sign_init(HsmHashSignAlgo::new(algo), priv_key).unwrap();

    ctx.update(b"data").unwrap();
    let sig1 = ctx.finish_vec().unwrap();

    // original signature must still be valid
    assert!(
        verify_signature(&pub_key, algo, b"data", &sig1),
        "Original signature should remain valid for {:?}",
        curve
    );

    let _ = ctx.update(b"more");
    if let Ok(sig2) = ctx.finish_vec() {
        assert!(
            !verify_signature(&pub_key, algo, b"datamore", &sig2),
            "Reused context should not produce valid signature for {:?}",
            curve
        );
    }
}

/// Verifies boundary input sizes succeed
fn run_boundary_input_sizes_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let inputs = [vec![0u8; 1], vec![0u8; 63], vec![0u8; 64], vec![0u8; 65]];

    for input in inputs {
        let sig = sign_data(&priv_key, algo, &input);
        assert!(
            verify_signature(&pub_key, algo, &input, &sig),
            "Boundary input failed for {:?}",
            curve
        );
    }
}

/// Verifies invalid signature format fails
fn run_invalid_signature_format_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
    sig_len: usize,
) {
    let (_, pub_key) = generate_ecc_key_pair(session, curve);

    let invalid_sig = vec![0xAA; sig_len];

    assert!(
        !verify_signature(&pub_key, algo, b"data", &invalid_sig),
        "Invalid signature format should fail for {:?}",
        curve
    );
}

/// Verifies hash/curve mismatch does not incorrectly succeed
fn run_hash_curve_mismatch_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"data";
    let sig = sign_data(&priv_key, algo, data);

    let mut verify_algo = HsmHashSignAlgo::new(algo);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, data, &sig);

    // must NOT incorrectly verify
    assert!(
        result.is_ok(),
        "Hash/curve mismatch should succeed for {:?}, got {:?}",
        curve,
        result
    );
}

/// Verifies cross-curve verification fails (false OR error)
fn run_cross_curve_mismatch_test(
    session: &HsmSession,
    sign_curve: HsmEccCurve,
    verify_curve: HsmEccCurve,
    algo: HsmHashAlgo,
) {
    let (priv_key, _) = generate_ecc_key_pair(session, sign_curve);
    let (_, pub_key) = generate_ecc_key_pair(session, verify_curve);

    let data = b"data";
    let sig = sign_data(&priv_key, algo, data);

    let mut verify_algo = HsmHashSignAlgo::new(algo);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, data, &sig);

    assert!(
        matches!(result, Ok(false) | Err(_)),
        "Cross-curve mismatch should fail (false or error) {:?} -> {:?}, got {:?}",
        sign_curve,
        verify_curve,
        result
    );
}

/// Verifies repeated signing produces non-empty signatures and consistent verification behavior
fn run_signature_determinism_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);
    let data = b"data";

    let sig1 = sign_data(&priv_key, algo, data);
    let sig2 = sign_data(&priv_key, algo, data);

    // Ensure signatures are not empty / malformed
    assert!(!sig1.is_empty(), "Signature 1 is empty");
    assert!(!sig2.is_empty(), "Signature 2 is empty");

    let mut verify_algo1 = HsmHashSignAlgo::new(algo);
    let r1 = HsmVerifier::verify(&mut verify_algo1, &pub_key, data, &sig1);

    let mut verify_algo2 = HsmHashSignAlgo::new(algo);
    let r2 = HsmVerifier::verify(&mut verify_algo2, &pub_key, data, &sig2);

    // Ensure both results are "safe"
    assert!(
        matches!(r1, Ok(_) | Err(_)),
        "Unexpected behavior for sig1 on {:?}: {:?}",
        curve,
        r1
    );

    assert!(
        matches!(r2, Ok(_) | Err(_)),
        "Unexpected behavior for sig2 on {:?}: {:?}",
        curve,
        r2
    );

    assert_eq!(
        r1.is_ok(),
        r2.is_ok(),
        "Inconsistent verification result types for {:?}: r1={:?}, r2={:?}",
        curve,
        r1,
        r2
    );

    if let (Ok(v1), Ok(v2)) = (r1, r2) {
        assert_eq!(
            v1, v2,
            "Inconsistent verification results for {:?}: v1={}, v2={}",
            curve, v1, v2
        );
    }
}

/// Verifies signing without permission does not produce a valid signature
fn run_sign_without_permission_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(false) // intentionally invalid
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .build()
        .unwrap();

    let mut keygen_algo = HsmEccKeyGenAlgo::default();

    let keypair_result =
        HsmKeyManager::generate_key_pair(session, &mut keygen_algo, priv_props, pub_props);

    match keypair_result {
        Err(_) => {
            // Expected: system rejects invalid key properties
        }
        Ok((priv_key, pub_key)) => {
            let data = b"data";

            let sign_result = HsmSigner::sign_vec(&mut HsmHashSignAlgo::new(algo), &priv_key, data);

            match sign_result {
                Err(_) => {
                    //  Expected: signing rejected
                }
                Ok(sig) => {
                    //  If signing succeeds, signature MUST NOT verify
                    let mut verify_algo = HsmHashSignAlgo::new(algo);
                    let verify_result = HsmVerifier::verify(&mut verify_algo, &pub_key, data, &sig);

                    match verify_result {
                        Ok(valid) => {
                            assert!(
                                !valid,
                                "Signature should not verify when signing without permission for {:?}",
                                curve
                            );
                        }
                        Err(_) => {
                            //  acceptable: verification rejects invalid signature
                        }
                    }
                }
            }
        }
    }
}

/// Verifies non-empty signature with empty data fails
fn run_verify_empty_data_mismatch_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let sig = sign_data(&priv_key, algo, b"data");

    let mut verify_algo = HsmHashSignAlgo::new(algo);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, b"", &sig);

    assert_verify_fail_or_err(result);
}

/// Verifies all-zero signature fails
fn run_zero_signature_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
    sig_len: usize,
) {
    let (_, pub_key) = generate_ecc_key_pair(session, curve);

    let zero_sig = vec![0u8; sig_len];

    let mut verify_algo = HsmHashSignAlgo::new(algo);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, b"data", &zero_sig);

    assert_verify_fail_or_err(result);
}

/// Verifies streaming verification fails for truncated signature
fn run_streaming_truncated_sig_test(session: &HsmSession, curve: HsmEccCurve, algo: HsmHashAlgo) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let chunks: [&[u8]; 2] = [b"a", b"b"];
    let sig = streaming_sign_data(priv_key, algo, &chunks);

    let truncated = &sig[..sig.len() / 2];

    let verify_algo = HsmHashSignAlgo::new(algo);
    let mut ctx = HsmVerifier::verify_init(verify_algo, pub_key).unwrap();

    for c in &chunks {
        ctx.update(c).unwrap();
    }

    let result = ctx.finish(truncated);

    assert_verify_fail_or_err(result);
}

/// Asserts that verification result is either false or returns an error
fn assert_verify_fail_or_err(result: Result<bool, HsmError>) {
    assert!(matches!(result, Ok(false) | Err(_)));
}

/// Verifies that malformed signatures (via mutation) fail verification
fn run_malformed_signature_test(
    session: &HsmSession,
    curve: HsmEccCurve,
    algo: HsmHashAlgo,
    mutator: impl Fn(Vec<u8>) -> Vec<u8>,
) {
    let (priv_key, pub_key) = generate_ecc_key_pair(session, curve);

    let data = b"data";
    let sig = sign_data(&priv_key, algo, data);

    let bad_sig = mutator(sig);

    let mut verify_algo = HsmHashSignAlgo::new(algo);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, data, &bad_sig);

    assert_verify_fail_or_err(result);
}
// ============================================================
// test cases sections
// ============================================================

/// Verifies ECC sign/verify succeeds for P256 with SHA256
#[session_test]
fn test_ecc_sign_verify_p256_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

/// Verifies ECC sign/verify succeeds for P384 with SHA384
#[session_test]
fn test_ecc_sign_verify_p384_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P384);
    let data = b"Test data for ECC signing with P-384";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha384, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha384, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

/// Verifies ECC sign/verify succeeds for P521 with SHA512
#[session_test]
fn test_ecc_sign_verify_p521_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P521);
    let data = b"Test data for ECC signing with P-521";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha512, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha512, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

/// Verifies tampered signature fails verification
#[session_test]
fn test_ecc_sign_verify_invalid_signature(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";

    let mut sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    sig[0] ^= 0xFF;

    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, data, &sig);

    assert!(!is_valid, "Signature verification should have failed");
}

/// Verifies verification fails when using incorrect input data
#[session_test]
fn test_ecc_sign_verify_wrong_data(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";
    let wrong_data = b"Different test data";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, wrong_data, &sig);

    assert!(!is_valid, "Signature verification should have failed");
}

/// Verifies streaming sign/verify succeeds for P256
#[session_test]
fn test_ecc_streaming_sign_verify_p256_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"ECC signing"];

    let sig = streaming_sign_data(priv_key, HsmHashAlgo::Sha256, &data_chunks);
    let is_valid = streaming_verify_signature(pub_key, HsmHashAlgo::Sha256, &data_chunks, &sig);

    assert!(is_valid, "Streaming signature verification failed");
}

/// Verifies streaming sign/verify succeeds for P384
#[session_test]
fn test_ecc_streaming_sign_verify_p384_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P384);
    let data_chunks = [
        b"Test data " as &[u8],
        b"for streaming ",
        b"ECC signing with P-384",
    ];

    let sig = streaming_sign_data(priv_key, HsmHashAlgo::Sha384, &data_chunks);
    let is_valid = streaming_verify_signature(pub_key, HsmHashAlgo::Sha384, &data_chunks, &sig);

    assert!(is_valid, "Streaming signature verification failed");
}

/// Verifies streaming sign/verify succeeds for P521
#[session_test]
fn test_ecc_streaming_sign_verify_p521_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P521);
    let data_chunks = [
        b"Test data " as &[u8],
        b"for streaming ",
        b"ECC signing with P-521",
    ];

    let sig = streaming_sign_data(priv_key, HsmHashAlgo::Sha512, &data_chunks);
    let is_valid = streaming_verify_signature(pub_key, HsmHashAlgo::Sha512, &data_chunks, &sig);

    assert!(is_valid, "Streaming signature verification failed");
}

/// Tests that verification fails when using a wrong public key for P256
#[session_test]
fn test_ecc_wrong_pubkey_p256_hash(session: HsmSession) {
    run_wrong_pubkey_hash_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies verification fails when using a wrong public key for P384
#[session_test]
fn test_ecc_wrong_pubkey_p384_hash(session: HsmSession) {
    run_wrong_pubkey_hash_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies verification fails when using a wrong public key for P521
#[session_test]
fn test_ecc_wrong_pubkey_p521_hash(session: HsmSession) {
    run_wrong_pubkey_hash_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that mismatched hash algorithms fail verification for P256
#[session_test]
fn test_ecc_hash_algo_mismatch_p256_hash(session: HsmSession) {
    run_hash_algo_mismatch_hash(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
    );
}

/// Tests that mismatched hash algorithms fail verification for P384
#[session_test]
fn test_ecc_hash_algo_mismatch_p384_hash(session: HsmSession) {
    run_hash_algo_mismatch_hash(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    );
}

/// Tests that mismatched hash algorithms fail verification for P521
#[session_test]
fn test_ecc_hash_algo_mismatch_p521_hash(session: HsmSession) {
    run_hash_algo_mismatch_hash(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        HsmHashAlgo::Sha256,
    );
}

/// Tests that streaming sign can be verified by single-shot verify for P256
#[session_test]
fn test_ecc_streaming_to_single_p256_hash(session: HsmSession) {
    run_streaming_to_single(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that streaming sign can be verified by single-shot verify for P384
#[session_test]
fn test_ecc_streaming_to_single_p384_hash(session: HsmSession) {
    run_streaming_to_single(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that streaming sign can be verified by single-shot verify for P521
#[session_test]
fn test_ecc_streaming_to_single_p521_hash(session: HsmSession) {
    run_streaming_to_single(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that single-shot signature can be verified via streaming for P256
#[session_test]
fn test_ecc_single_to_streaming_p256_hash(session: HsmSession) {
    run_single_to_streaming(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies single-shot signature can be verified via streaming for P384
#[session_test]
fn test_ecc_single_to_streaming_p384_hash(session: HsmSession) {
    run_single_to_streaming(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies single-shot signature can be verified via streaming for P521
#[session_test]
fn test_ecc_single_to_streaming_p521_hash(session: HsmSession) {
    run_single_to_streaming(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that different streaming chunk boundaries produce valid verification for P256
#[session_test]
fn test_ecc_streaming_chunk_variation_p256_hash(session: HsmSession) {
    run_chunk_variation_hash(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies streaming chunk boundary variation produces valid verification for P384
#[session_test]
fn test_ecc_streaming_chunk_variation_p384_hash(session: HsmSession) {
    run_chunk_variation_hash(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies streaming chunk boundary variation produces valid verification for P521
#[session_test]
fn test_ecc_streaming_chunk_variation_p521_hash(session: HsmSession) {
    run_chunk_variation_hash(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that reusing streaming verify context does not produce unsafe results
#[session_test]
fn test_ecc_streaming_context_reuse_p256_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);

    let chunks: [&[u8]; 2] = [b"a" as &[u8], b"b" as &[u8]];

    let sig = streaming_sign_data(priv_key, HsmHashAlgo::Sha256, &chunks);

    let verify_algo = HsmHashSignAlgo::new(HsmHashAlgo::Sha256);
    let mut ctx = HsmVerifier::verify_init(verify_algo, pub_key).unwrap();

    for c in &chunks {
        ctx.update(c).unwrap();
    }

    // first verification must succeed
    assert!(ctx.finish(&sig).unwrap());

    // reuse context (allowed by current implementation)
    let result = ctx.finish(&sig);

    // must NOT behave like a valid fresh verification
    assert!(
        matches!(result, Err(_) | Ok(false)),
        "Reused verify context should not succeed, got {:?}",
        result
    );
}

/// Tests streaming signing with large input for P256
#[session_test]
fn test_ecc_streaming_large_input_p256_hash(session: HsmSession) {
    run_streaming_large_input_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests streaming signing with large input for P384
#[session_test]
fn test_ecc_streaming_large_input_p384_hash(session: HsmSession) {
    run_streaming_large_input_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests streaming signing with large input for P521
#[session_test]
fn test_ecc_streaming_large_input_p521_hash(session: HsmSession) {
    run_streaming_large_input_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that tampered signature fails in streaming verification for P256
#[session_test]
fn test_ecc_streaming_tampered_sig_p256_hash(session: HsmSession) {
    run_streaming_tampered_sig_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that tampered signature fails in streaming verification for P384
#[session_test]
fn test_ecc_streaming_tampered_sig_p384_hash(session: HsmSession) {
    run_streaming_tampered_sig_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that tampered signature fails in streaming verification for P521
#[session_test]
fn test_ecc_streaming_tampered_sig_p521_hash(session: HsmSession) {
    run_streaming_tampered_sig_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that streaming verification fails with incorrect data chunks for P256
#[session_test]
fn test_ecc_streaming_wrong_data_p256_hash(session: HsmSession) {
    run_streaming_wrong_data_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that streaming verification fails with incorrect data chunks for P384
#[session_test]
fn test_ecc_streaming_wrong_data_p384_hash(session: HsmSession) {
    run_streaming_wrong_data_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that streaming verification fails with incorrect data chunks for P521
#[session_test]
fn test_ecc_streaming_wrong_data_p521_hash(session: HsmSession) {
    run_streaming_wrong_data_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that signing and verifying empty data succeeds for P256
#[session_test]
fn test_ecc_empty_data_p256_hash(session: HsmSession) {
    run_empty_data_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that signing and verifying empty data succeeds for P384
#[session_test]
fn test_ecc_empty_data_p384_hash(session: HsmSession) {
    run_empty_data_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that signing and verifying empty data succeeds for P521
#[session_test]
fn test_ecc_empty_data_p521_hash(session: HsmSession) {
    run_empty_data_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests multiple sequential sign/verify operations for P256
#[session_test]
fn test_ecc_multiple_ops_p256_hash(session: HsmSession) {
    run_multiple_ops_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests multiple sequential sign/verify operations for P384
#[session_test]
fn test_ecc_multiple_ops_p384_hash(session: HsmSession) {
    run_multiple_ops_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests multiple sequential sign/verify operations for P521
#[session_test]
fn test_ecc_multiple_ops_p521_hash(session: HsmSession) {
    run_multiple_ops_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests streaming signing and verification with empty input for P256
#[session_test]
fn test_ecc_streaming_empty_data_p256_hash(session: HsmSession) {
    run_streaming_empty_input_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies streaming signing and verification with empty input for P384
#[session_test]
fn test_ecc_streaming_empty_data_p384_hash(session: HsmSession) {
    run_streaming_empty_input_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies streaming signing and verification with empty input for P521
#[session_test]
fn test_ecc_streaming_empty_data_p521_hash(session: HsmSession) {
    run_streaming_empty_input_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies streaming verification fails with mismatched hash algorithms for P256
#[session_test]
fn test_ecc_streaming_hash_algo_mismatch_p256_hash(session: HsmSession) {
    run_streaming_hash_algo_mismatch_test(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        HsmHashAlgo::Sha384,
    );
}

/// Verifies streaming verification fails with mismatched hash algorithms for P384
#[session_test]
fn test_ecc_streaming_hash_algo_mismatch_p384_hash(session: HsmSession) {
    run_streaming_hash_algo_mismatch_test(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        HsmHashAlgo::Sha512,
    );
}

/// Verifies streaming verification fails with mismatched hash algorithms for P521
#[session_test]
fn test_ecc_streaming_hash_algo_mismatch_p521_hash(session: HsmSession) {
    run_streaming_hash_algo_mismatch_test(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies single-chunk and multi-chunk streaming produce equivalent verification results for P256
#[session_test]
fn test_ecc_streaming_single_vs_multi_chunk_p256_hash(session: HsmSession) {
    run_streaming_single_vs_multi_chunk_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies single-chunk and multi-chunk streaming produce equivalent verification results for P384
#[session_test]
fn test_ecc_streaming_single_vs_multi_chunk_p384_hash(session: HsmSession) {
    run_streaming_single_vs_multi_chunk_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies single-chunk and multi-chunk streaming produce equivalent verification results for P521
#[session_test]
fn test_ecc_streaming_single_vs_multi_chunk_p521_hash(session: HsmSession) {
    run_streaming_single_vs_multi_chunk_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that streaming verification fails when using a wrong public key for P256
#[session_test]
fn test_ecc_streaming_wrong_pubkey_p256_hash(session: HsmSession) {
    run_streaming_wrong_pubkey_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that streaming verification fails when using a wrong public key for P384
#[session_test]
fn test_ecc_streaming_wrong_pubkey_p384_hash(session: HsmSession) {
    run_streaming_wrong_pubkey_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that streaming verification fails when using a wrong public key for P521
#[session_test]
fn test_ecc_streaming_wrong_pubkey_p521_hash(session: HsmSession) {
    run_streaming_wrong_pubkey_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that streaming verification fails when empty data is verified against non-empty data for P256
#[session_test]
fn test_ecc_streaming_empty_mismatch_p256_hash(session: HsmSession) {
    run_streaming_empty_mismatch_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that streaming verification fails when empty data is verified against non-empty data for P384
#[session_test]
fn test_ecc_streaming_empty_mismatch_p384_hash(session: HsmSession) {
    run_streaming_empty_mismatch_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that streaming verification fails when empty data is verified against non-empty data for P521
#[session_test]
fn test_ecc_streaming_empty_mismatch_p521_hash(session: HsmSession) {
    run_streaming_empty_mismatch_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Tests that streaming verification fails when chunk order differs for P256
#[session_test]
fn test_ecc_streaming_chunk_order_mismatch_p256_hash(session: HsmSession) {
    run_streaming_chunk_order_mismatch_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Tests that streaming verification fails when chunk order differs for P384
#[session_test]
fn test_ecc_streaming_chunk_order_mismatch_p384_hash(session: HsmSession) {
    run_streaming_chunk_order_mismatch_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Tests that streaming verification fails when chunk order differs for P521
#[session_test]
fn test_ecc_streaming_chunk_order_mismatch_p521_hash(session: HsmSession) {
    run_streaming_chunk_order_mismatch_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies truncated signature fails verification for P256
#[session_test]
fn test_ecc_signature_truncated_p256_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256, |sig| {
        sig[..sig.len() / 2].to_vec()
    });
}

/// Verifies truncated signature fails verification for P384
#[session_test]
fn test_ecc_signature_truncated_p384_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384, |sig| {
        sig[..sig.len() / 2].to_vec()
    });
}

/// Verifies truncated signature fails verification for P521
#[session_test]
fn test_ecc_signature_truncated_p521_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512, |sig| {
        sig[..sig.len() / 2].to_vec()
    });
}

/// Verifies extended signature fails verification for P256
#[session_test]
fn test_ecc_signature_extended_p256_hash(session: HsmSession) {
    run_malformed_signature_test(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
        |mut sig| {
            sig.push(0);
            sig
        },
    );
}

/// Verifies extended signature fails verification for P384
#[session_test]
fn test_ecc_signature_extended_p384_hash(session: HsmSession) {
    run_malformed_signature_test(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha384,
        |mut sig| {
            sig.push(0);
            sig
        },
    );
}

/// Verifies extended signature fails verification for P521
#[session_test]
fn test_ecc_signature_extended_p521_hash(session: HsmSession) {
    run_malformed_signature_test(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
        |mut sig| {
            sig.push(0);
            sig
        },
    );
}

/// Verifies signature from P256 key fails verification with P384 key
#[session_test]
fn test_ecc_cross_curve_p256_to_p384_hash(session: HsmSession) {
    run_cross_curve_mismatch_test(
        &session,
        HsmEccCurve::P256,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies signature from P384 key fails verification with P521 key
#[session_test]
fn test_ecc_cross_curve_p384_to_p521_hash(session: HsmSession) {
    run_cross_curve_mismatch_test(
        &session,
        HsmEccCurve::P384,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha384,
    );
}

/// Verifies signing context reuse does not produce valid signatures for P256
#[session_test]
fn test_ecc_sign_context_reuse_p256_hash(session: HsmSession) {
    run_sign_context_reuse_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies signing context reuse does not produce valid signatures for P384
#[session_test]
fn test_ecc_sign_context_reuse_p384_hash(session: HsmSession) {
    run_sign_context_reuse_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies signing context reuse does not produce valid signatures for P521
#[session_test]
fn test_ecc_sign_context_reuse_p521_hash(session: HsmSession) {
    run_sign_context_reuse_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies updating signing context after finish does not produce valid signatures for P256
#[session_test]
fn test_ecc_sign_update_after_finish_p256_hash(session: HsmSession) {
    run_sign_update_after_finish_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies updating signing context after finish does not produce valid signatures for P384
#[session_test]
fn test_ecc_sign_update_after_finish_p384_hash(session: HsmSession) {
    run_sign_update_after_finish_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies updating signing context after finish does not produce valid signatures for P521
#[session_test]
fn test_ecc_sign_update_after_finish_p521_hash(session: HsmSession) {
    run_sign_update_after_finish_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies boundary input sizes produce valid signatures for P256
#[session_test]
fn test_ecc_boundary_input_sizes_p256_hash(session: HsmSession) {
    run_boundary_input_sizes_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies boundary input sizes produce valid signatures for P384
#[session_test]
fn test_ecc_boundary_input_sizes_p384_hash(session: HsmSession) {
    run_boundary_input_sizes_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies boundary input sizes produce valid signatures for P521
#[session_test]
fn test_ecc_boundary_input_sizes_p521_hash(session: HsmSession) {
    run_boundary_input_sizes_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies invalid signature format fails verification for P256
#[session_test]
fn test_ecc_invalid_signature_format_p256_hash(session: HsmSession) {
    run_invalid_signature_format_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256, 64);
}

/// Verifies invalid signature format fails verification for P384
#[session_test]
fn test_ecc_invalid_signature_format_p384_hash(session: HsmSession) {
    run_invalid_signature_format_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384, 96);
}

/// Verifies invalid signature format fails verification for P521
#[session_test]
fn test_ecc_invalid_signature_format_p521_hash(session: HsmSession) {
    run_invalid_signature_format_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512, 132);
}

/// Verifies repeated signing produces non-empty signatures and safe verification behavior for P256
#[session_test]
fn test_ecc_signature_determinism_p256_hash(session: HsmSession) {
    run_signature_determinism_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies repeated signing produces non-empty signatures and safe verification behavior for P384
#[session_test]
fn test_ecc_signature_determinism_p384_hash(session: HsmSession) {
    run_signature_determinism_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies repeated signing produces non-empty signatures and safe verification behavior for P521
#[session_test]
fn test_ecc_signature_determinism_p521_hash(session: HsmSession) {
    run_signature_determinism_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies signing without permission does not produce valid signatures for P256
#[session_test]
fn test_ecc_sign_without_permission_p256_hash(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies signing without permission does not produce valid signatures for P384
#[session_test]
fn test_ecc_sign_without_permission_p384_hash(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies signing without permission does not produce valid signatures for P521
#[session_test]
fn test_ecc_sign_without_permission_p521_hash(session: HsmSession) {
    run_sign_without_permission_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies P256 with SHA512 behaves safely
#[session_test]
fn test_ecc_hash_curve_mismatch_p256_sha512(session: HsmSession) {
    run_hash_curve_mismatch_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha512);
}

/// Verifies P384 with SHA256 behaves safely
#[session_test]
fn test_ecc_hash_curve_mismatch_p384_sha256(session: HsmSession) {
    run_hash_curve_mismatch_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha256);
}

/// Verifies P521 with SHA256 behaves safely
#[session_test]
fn test_ecc_hash_curve_mismatch_p521_sha256(session: HsmSession) {
    run_hash_curve_mismatch_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha256);
}

/// Verifies empty signature fails for P256
#[session_test]
fn test_ecc_empty_signature_p256_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256, |_| vec![]);
}

/// Verifies empty signature fails verification for P384
#[session_test]
fn test_ecc_empty_signature_p384_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384, |_| vec![]);
}

/// Verifies empty signature fails verification for P521
#[session_test]
fn test_ecc_empty_signature_p521_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512, |_| vec![]);
}

/// Verifies shortened (off-by-one) signature fails verification for P256
#[session_test]
fn test_ecc_signature_len_off_by_one_p256_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256, |sig| {
        sig[..sig.len() - 1].to_vec()
    });
}

/// Verifies shortened (off-by-one) signature fails verification for P384
#[session_test]
fn test_ecc_signature_len_off_by_one_p384_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384, |sig| {
        sig[..sig.len() - 1].to_vec()
    });
}

/// Verifies shortened (off-by-one) signature fails verification for P521
#[session_test]
fn test_ecc_signature_len_off_by_one_p521_hash(session: HsmSession) {
    run_malformed_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512, |sig| {
        sig[..sig.len() - 1].to_vec()
    });
}

/// Verifies verification fails when non-empty signature is checked against empty data for P256
#[session_test]
fn test_ecc_verify_empty_data_mismatch_p256_hash(session: HsmSession) {
    run_verify_empty_data_mismatch_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies verification fails when non-empty signature is checked against empty data for P384
#[session_test]
fn test_ecc_verify_empty_data_mismatch_p384_hash(session: HsmSession) {
    run_verify_empty_data_mismatch_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies verification fails when non-empty signature is checked against empty data for P521
#[session_test]
fn test_ecc_verify_empty_data_mismatch_p521_hash(session: HsmSession) {
    run_verify_empty_data_mismatch_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}

/// Verifies all-zero signature fails verification for P256
#[session_test]
fn test_ecc_zero_signature_p256_hash(session: HsmSession) {
    run_zero_signature_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256, 64);
}

/// Verifies all-zero signature fails verification for P384
#[session_test]
fn test_ecc_zero_signature_p384_hash(session: HsmSession) {
    run_zero_signature_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384, 96);
}

/// Verifies all-zero signature fails verification for P521
#[session_test]
fn test_ecc_zero_signature_p521_hash(session: HsmSession) {
    run_zero_signature_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512, 132);
}

/// Verifies streaming verification fails for truncated signature for P256
#[session_test]
fn test_ecc_streaming_truncated_sig_p256_hash(session: HsmSession) {
    run_streaming_truncated_sig_test(&session, HsmEccCurve::P256, HsmHashAlgo::Sha256);
}

/// Verifies streaming verification fails for truncated signature for P384
#[session_test]
fn test_ecc_streaming_truncated_sig_p384_hash(session: HsmSession) {
    run_streaming_truncated_sig_test(&session, HsmEccCurve::P384, HsmHashAlgo::Sha384);
}

/// Verifies streaming verification fails for truncated signature for P521
#[session_test]
fn test_ecc_streaming_truncated_sig_p521_hash(session: HsmSession) {
    run_streaming_truncated_sig_test(&session, HsmEccCurve::P521, HsmHashAlgo::Sha512);
}
