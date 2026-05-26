// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::*;

use super::*;

// ================================
// Helper functions
// ================================

fn import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    try_import_rsa_key_pair(session, der, bits, ImportedRsaKeyUsage::SignVerify, true)
}

/// Helper to perform streaming RSA signing over multiple data chunks
fn streaming_sign_data(
    priv_key: HsmRsaPrivateKey,
    sign_algo: HsmRsaHashSignAlgo,
    data_chunks: &[&[u8]],
) -> Vec<u8> {
    let mut sign_ctx =
        HsmSigner::sign_init(sign_algo, priv_key).expect("Failed to initialize signing context");

    for chunk in data_chunks {
        sign_ctx.update(chunk).expect("Failed to update");
    }

    sign_ctx.finish_vec().expect("Failed to finish signature")
}

/// Helper to perform streaming RSA signature verification over multiple data chunks
fn streaming_verify_signature(
    pub_key: HsmRsaPublicKey,
    verify_algo: HsmRsaHashSignAlgo,
    data_chunks: &[&[u8]],
    signature: &[u8],
) -> bool {
    let mut verify_ctx = HsmVerifier::verify_init(verify_algo, pub_key)
        .expect("Failed to initialize verification context");

    for chunk in data_chunks {
        verify_ctx.update(chunk).expect("Failed to update");
    }

    verify_ctx
        .finish(signature)
        .expect("Failed to finish verification")
}

/// Assert that a one-shot RSA hash signature verifies successfully
fn assert_one_shot_verify_succeeds(
    pub_key: &HsmRsaPublicKey,
    algo: &mut HsmRsaHashSignAlgo,
    message: &[u8],
    signature: &[u8],
) {
    let is_valid = HsmVerifier::verify(algo, pub_key, message, signature)
        .expect("positive control verification should succeed");

    assert!(
        is_valid,
        "positive control verification should return true before negative mutation"
    );
}

/// Assert that a streaming RSA hash signature verifies successfully
fn assert_streaming_verify_succeeds(
    pub_key: HsmRsaPublicKey,
    verify_algo: HsmRsaHashSignAlgo,
    data_chunks: &[&[u8]],
    signature: &[u8],
) {
    let is_valid = streaming_verify_signature(pub_key, verify_algo, data_chunks, signature);

    assert!(
        is_valid,
        "positive control streaming verification should return true before negative mutation"
    );
}
// ============================================================
// test case section
// ============================================================

/// Ensure RSA-2048 PKCS#1 signing and verification succeeds
#[session_test]
fn test_rsa_2048_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let message = b"Hello, RSA 2048!";
    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-3072 PKCS#1 signing and verification succeeds
#[session_test]
fn test_rsa_3072_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 3072).expect("RSA import should succeed");

    let message = b"Hello, RSA 3072!";
    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha384);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-4096 PKCS#1 signing and verification succeeds
#[session_test]
fn test_rsa_4096_pkcs1_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 4096).expect("RSA import should succeed");

    let message = b"Hello, RSA 4096!";
    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha512);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-2048 PSS signing and verification succeeds
#[session_test]
fn test_rsa_2048_pss_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let message = b"Hello, RSA 2048!";
    let mut algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-3072 PSS signing and verification succeeds
#[session_test]
fn test_rsa_3072_pss_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 3072).expect("RSA import should succeed");

    let message = b"Hello, RSA 3072!";
    let mut algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha384, 32);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-4096 PSS signing and verification succeeds
#[session_test]
fn test_rsa_4096_pss_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 4096).expect("RSA import should succeed");

    let message = b"Hello, RSA 4096!";
    let mut algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha512, 32);

    let signature =
        HsmSigner::sign_vec(&mut algo, &priv_key, message).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, message, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

/// Ensure RSA-2048 PKCS#1 streaming sign and verify succeeds
#[session_test]
fn test_rsa_2048_pkcs1_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha256;
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Ensure RSA-3072 PKCS#1 streaming sign and verify succeeds
#[session_test]
fn test_rsa_3072_pkcs1_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 3072).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha384;
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Ensure RSA-4096 PKCS#1 streaming sign and verify succeeds
#[session_test]
fn test_rsa_4096_pkcs1_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 4096).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha512;
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Ensure RSA-2048 PSS streaming sign and verify succeeds
#[session_test]
fn test_rsa_2048_pss_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha256;
    let sign_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Ensure RSA-3072 PSS streaming sign and verify succeeds
#[session_test]
fn test_rsa_3072_pss_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 3072).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha384;
    let sign_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Ensure RSA-4096 PSS streaming sign and verify succeeds
#[session_test]
fn test_rsa_4096_pss_streaming_sign_verify(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 4096).expect("RSA import should succeed");

    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"RSA signing"];
    let hash_algo = HsmHashAlgo::Sha512;
    let sign_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);
    let verify_algo = HsmRsaHashSignAlgo::with_pss_padding(hash_algo, 32);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &sig);
    assert!(is_valid, "Streaming signature verification failed");
}

/// Verifies that RSA sign context rejects update and finish after successful finish.
#[session_test]
fn test_rsa_streaming_sign_update_after_finish_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, _pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx = HsmSigner::sign_init(sign_algo, priv_key).expect("sign_init should succeed");

    ctx.update(b"test data").expect("update should succeed");

    let _sig = ctx.finish_vec().expect("first finish should succeed");

    // update after finish must fail
    let res = ctx.update(b"more data");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState, got {:?}",
        res
    );

    // second finish must fail
    let res = ctx.finish_vec();
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState, got {:?}",
        res
    );
}

/// Verifies that RSA verify context rejects update and finish after successful finish.
#[session_test]
fn test_rsa_streaming_verify_update_after_finish_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let data = b"test data";
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &[data as &[u8]]);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    ctx.update(data).expect("update should succeed");

    let result = ctx.finish(&sig).expect("first finish should succeed");
    assert!(result, "first verification should succeed");

    // update after finish must fail
    let res = ctx.update(b"more data");
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "update() after finish() should return InvalidContextState, got {:?}",
        res
    );

    // second finish must fail
    let res = ctx.finish(&sig);
    assert!(
        matches!(res, Err(HsmError::InvalidContextState)),
        "finish() after finish() should return InvalidContextState, got {:?}",
        res
    );
}

/// Ensure streaming and one-shot produce same signature (PKCS1 only)
#[session_test]
fn test_rsa_hash_sign_streaming_vs_single_same(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, _) = import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let message = b"hello world";

    let mut algo1 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig1 = HsmSigner::sign_vec(&mut algo1, &priv_key, message).expect("Failed to sign data");

    let chunks = [b"hello " as &[u8], b"world"];
    let algo2 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig2 = streaming_sign_data(priv_key, algo2, &chunks);

    assert_eq!(sig1, sig2);
}

/// Ensure different chunk order produces different signature
#[session_test]
fn test_rsa_streaming_chunk_order_matters(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, _) = import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    // Create separate algo instances (no clone needed)
    let algo1 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let algo2 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let sig1 = streaming_sign_data(priv_key.clone(), algo1, &[b"a", b"b"]);
    let sig2 = streaming_sign_data(priv_key, algo2, &[b"b", b"a"]);

    assert_ne!(sig1, sig2);
}

/// Ensure empty streaming input produces a valid signature
#[session_test]
fn test_rsa_streaming_empty_input_succeeds(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let mut sign_ctx =
        HsmSigner::sign_init(algo, priv_key).expect("Failed to initialize signing context");

    // no update()

    let sig = sign_ctx
        .finish_vec()
        .expect("empty input should still produce signature");

    // verify it
    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut verify_ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    let is_valid = verify_ctx
        .finish(&sig)
        .expect("Failed to finish verification");

    assert!(is_valid, "Empty input signature should be valid");
}

/// Ensure streaming verify fails for corrupted signature
#[session_test]
fn test_rsa_streaming_verify_modified_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let data_chunks = [b"hello " as &[u8], b"world"];
    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let sig = streaming_sign_data(priv_key, sign_algo, &data_chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &data_chunks, &sig);

    let mut corrupted_sig = sig.clone();
    corrupted_sig[0] ^= 0xFF;

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    for c in data_chunks {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&corrupted_sig);

    assert!(
        matches!(result, Ok(false)),
        "finish with modified sig should not succeed, got {:?}",
        result
    );
}

/// Ensure streaming verify fails for modified data
#[session_test]
fn test_rsa_streaming_verify_wrong_data_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let data1 = [b"hello " as &[u8], b"world"];
    let data2 = [b"hello " as &[u8], b"WORLD"]; // changed

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &data1);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &data1, &sig);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    for c in data2 {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&sig);

    assert!(
        matches!(result, Ok(false)),
        "verify with wrong data should not succeed, got {:?}",
        result
    );
}

/// Ensure streaming verify fails with mismatched padding
#[session_test]
fn test_rsa_streaming_pkcs1_vs_pss_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let chunks = [b"hello " as &[u8], b"world"];

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &chunks, &sig);

    let verify_algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);

    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    for c in chunks {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&sig);

    assert!(
        matches!(result, Ok(false)),
        "finish with mismatched padding should not succeed, got {:?}",
        result
    );
}

/// Ensure update with empty chunk behaves correctly
#[session_test]
fn test_rsa_streaming_empty_chunk_update(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");

    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let mut ctx =
        HsmSigner::sign_init(algo, priv_key).expect("Failed to initialize signing context");

    ctx.update(b"").expect("update should succeed"); // empty chunk

    let sig = ctx.finish_vec().expect("first finish should succeed");

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut vctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    let is_valid = vctx.finish(&sig).expect("Failed to finish verification");

    assert!(is_valid);
}

/// Verifies RSA hash-sign streaming works for large multi-chunk input.
#[session_test]
fn test_rsa_streaming_large_input(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = priv_key.to_vec().expect("Failed to export RSA key");
    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let chunk1 = vec![0x11; 4096];
    let chunk2 = vec![0x22; 4096];
    let chunk3 = vec![0x33; 4096];

    let data_chunks = [chunk1.as_slice(), chunk2.as_slice(), chunk3.as_slice()];

    let hash_algo = HsmHashAlgo::Sha256;

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let signature = streaming_sign_data(priv_key, sign_algo, &data_chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(hash_algo);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &data_chunks, &signature);

    assert!(
        is_valid,
        "Streaming verification should succeed for large input"
    );
}

/// Ensure streaming verify fails with wrong public key
#[session_test]
fn test_rsa_streaming_verify_wrong_key_fails(session: HsmSession) {
    let priv1 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let priv2 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");

    let der1 = priv1.to_vec().expect("Failed to export RSA Key");
    let der2 = priv2.to_vec().expect("Failed to export RSA Key");

    let (priv1, pub1) = import_rsa_key(&session, &der1, 2048).expect("RSA import should succeed");
    let (_, pub2) = import_rsa_key(&session, &der2, 2048).expect("RSA import should succeed");

    let chunks = [b"hello " as &[u8], b"world"];

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv1, sign_algo, &chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub1, verify_algo, &chunks, &sig);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx = HsmVerifier::verify_init(verify_algo, pub2).expect("verify_init should succeed");

    for c in chunks {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&sig);

    assert!(
        matches!(result, Ok(false)),
        "verify with wrong key should not succeed, got {:?}",
        result
    );
}

/// Ensure streaming verify fails with empty signature
#[session_test]
fn test_rsa_streaming_verify_empty_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (_priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let chunks = [b"hello" as &[u8]];

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");
    for c in chunks {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&[]); // empty sig

    assert!(
        matches!(result, Ok(false)),
        "finish with empty sig should not succeed, got {:?}",
        result
    );
}

/// Ensure streaming verify fails with truncated signature
#[session_test]
fn test_rsa_streaming_verify_truncated_signature_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let chunks = [b"hello " as &[u8], b"world"];

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &chunks, &sig);

    let mut truncated_sig = sig.clone();
    truncated_sig.truncate(truncated_sig.len() / 2);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    for c in chunks {
        ctx.update(c).expect("update should succeed");
    }

    let result = ctx.finish(&truncated_sig);

    assert!(
        matches!(result, Ok(false)),
        "verify with truncated sig should not succeed, got {:?}",
        result
    );
}

/// Ensure PSS signatures are non-deterministic
#[session_test]
fn test_rsa_pss_non_deterministic(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, _) = import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut algo1 = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);
    let mut algo2 = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);

    let sig1 = HsmSigner::sign_vec(&mut algo1, &priv_key, msg).expect("Failed to sign data");
    let sig2 = HsmSigner::sign_vec(&mut algo2, &priv_key, msg).expect("Failed to sign data");

    assert_ne!(sig1, sig2);
}

/// Ensure verification fails when signing and verifying use different hash algorithms
#[session_test]
fn test_rsa_verify_wrong_hash_algo_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv_key, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, msg, &sig);

    let mut wrong_verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha384);
    let result = HsmVerifier::verify(&mut wrong_verify_algo, &pub_key, msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure PSS verification fails when salt length differs from signing
#[session_test]
fn test_rsa_pss_salt_len_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv_key, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 32);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, msg, &sig);

    let mut wrong_verify_algo = HsmRsaHashSignAlgo::with_pss_padding(HsmHashAlgo::Sha256, 20);
    let result = HsmVerifier::verify(&mut wrong_verify_algo, &pub_key, msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure one-shot verification fails when signature is corrupted
#[session_test]
fn test_rsa_verify_modified_signature_fails_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv_key, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, msg, &sig);

    let mut corrupted_sig = sig.clone();
    corrupted_sig[0] ^= 0xFF;

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, msg, &corrupted_sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure one-shot verification fails when message differs from signed data
#[session_test]
fn test_rsa_verify_wrong_data_fails_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let signed_msg = b"hello";
    let wrong_msg = b"HELLO";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, signed_msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, signed_msg, &sig);

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, wrong_msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure signing and verifying an empty message succeeds (one-shot path)
#[session_test]
fn test_rsa_sign_empty_message_one_shot(session: HsmSession) {
    let generated_priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let priv_key_der = generated_priv_key
        .to_vec()
        .expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &priv_key_der, 2048).expect("RSA import should succeed");

    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let sig = HsmSigner::sign_vec(&mut algo, &priv_key, b"").expect("Failed to sign data");

    let is_valid =
        HsmVerifier::verify(&mut algo, &pub_key, b"", &sig).expect("Failed to verify signature");

    assert!(is_valid);
}

/// Ensure verification fails for truncated signature length
#[session_test]
fn test_rsa_verify_truncated_signature_fails(session: HsmSession) {
    let generated_priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let priv_key_der = generated_priv_key
        .to_vec()
        .expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &priv_key_der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv_key, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, msg, &sig);

    let truncated_sig = &sig[..10];

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, msg, truncated_sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure PKCS#1 signatures are deterministic for the same key and message
#[session_test]
fn test_rsa_pkcs1_deterministic(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, _) = import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";

    let mut algo1 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut algo2 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let sig1 = HsmSigner::sign_vec(&mut algo1, &priv_key, msg).expect("Failed to sign data");
    let sig2 = HsmSigner::sign_vec(&mut algo2, &priv_key, msg).expect("Failed to sign data");
    assert_eq!(sig1, sig2);
}

/// Ensure verification fails when using a public key of mismatched size
#[session_test]
fn test_rsa_verify_mismatched_key_size_fails(session: HsmSession) {
    let priv1 = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let priv2 = RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");

    let der1 = priv1.to_vec().expect("Failed to export RSA Key");
    let der2 = priv2.to_vec().expect("Failed to export RSA Key");

    let (priv1, pub1) = import_rsa_key(&session, &der1, 2048).expect("RSA import should succeed");
    let (_, pub2) = import_rsa_key(&session, &der2, 3072).expect("RSA import should succeed");

    let msg = b"hello";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv1, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub1, &mut verify_algo, msg, &sig);

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub2, msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "Verification should not succeed, got {:?}",
        result
    );
}

/// Ensure streaming sign without update equals one-shot empty input
#[session_test]
fn test_streaming_no_update_equals_empty_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let algo1 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig1 = streaming_sign_data(priv_key.clone(), algo1, &[]);

    let mut algo2 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig2 = HsmSigner::sign_vec(&mut algo2, &priv_key, b"").expect("Failed to sign data");

    assert_eq!(sig1, sig2);

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, b"", &sig1);
}

/// Ensure streaming signature over non-empty input does not verify empty input
#[session_test]
fn test_rsa_streaming_non_empty_signature_empty_data_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let chunks = [b"hello" as &[u8]];

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &chunks);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &chunks, &sig);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    let result = ctx.finish(&sig);

    assert!(
        matches!(result, Ok(false)),
        "non-empty-input signature should not verify empty streaming input, got {:?}",
        result
    );
}

/// Ensure streaming and one-shot signatures differ when data differs
#[session_test]
fn test_streaming_vs_single_mismatch_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, _pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let mut algo1 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig1 = HsmSigner::sign_vec(&mut algo1, &priv_key, b"hello").expect("Failed to sign data");

    let algo2 = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig2 = streaming_sign_data(priv_key, algo2, &[b"hell", b"o!"]); // different

    assert_ne!(sig1, sig2);
}

/// Ensure multiple empty chunks behave same as empty input
#[session_test]
fn test_streaming_multiple_empty_chunks(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let sig = streaming_sign_data(priv_key, algo, &[b"", b"", b""]);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let is_valid = streaming_verify_signature(pub_key, verify_algo, &[b""], &sig);

    assert!(is_valid);
}

/// Ensure unwrapping key cannot be used for signing
#[session_test]
fn test_unwrapping_key_cannot_sign(session: HsmSession) {
    let (priv_key, _) = get_rsa_unwrapping_key_pair(&session);

    let mut algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let result = HsmSigner::sign_vec(&mut algo, &priv_key, b"data");

    let err = result.expect_err("Unwrapping key should not allow signing");

    assert_eq!(
        err,
        HsmError::InvalidKey,
        "Expected unwrapping key signing to fail with InvalidKey"
    );
}

/// Ensure one-shot verify fails with an empty signature, even for an empty message
#[session_test]
fn test_rsa_verify_empty_signature_empty_message_fails_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (_priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);

    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, b"", &[]);

    assert!(
        matches!(result, Ok(false)),
        "verify with empty signature should not succeed, got {:?}",
        result
    );
}

/// Ensure a signature over an empty message does not verify non-empty data
#[session_test]
fn test_rsa_empty_message_signature_wrong_data_fails_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let empty_msg = b"";
    let wrong_msg = b"not empty";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig =
        HsmSigner::sign_vec(&mut sign_algo, &priv_key, empty_msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, empty_msg, &sig);

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, wrong_msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "empty-message signature should not verify non-empty data, got {:?}",
        result
    );
}

/// Ensure a signature over non-empty data does not verify an empty message
#[session_test]
fn test_rsa_non_empty_message_signature_empty_data_fails_one_shot(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let msg = b"hello";
    let empty_msg = b"";

    let mut sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = HsmSigner::sign_vec(&mut sign_algo, &priv_key, msg).expect("Failed to sign data");

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_one_shot_verify_succeeds(&pub_key, &mut verify_algo, msg, &sig);

    let mut verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let result = HsmVerifier::verify(&mut verify_algo, &pub_key, empty_msg, &sig);

    assert!(
        matches!(result, Ok(false)),
        "non-empty-message signature should not verify empty data, got {:?}",
        result
    );
}

/// Ensure streaming signature over empty input does not verify non-empty chunks
#[session_test]
fn test_rsa_streaming_empty_input_signature_wrong_data_fails(session: HsmSession) {
    let priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (priv_key, pub_key) =
        import_rsa_key(&session, &der, 2048).expect("RSA import should succeed");

    let sign_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let sig = streaming_sign_data(priv_key, sign_algo, &[]);

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    assert_streaming_verify_succeeds(pub_key.clone(), verify_algo, &[], &sig);

    let wrong_chunks = [b"not empty" as &[u8]];

    let verify_algo = HsmRsaHashSignAlgo::with_pkcs1_padding(HsmHashAlgo::Sha256);
    let mut ctx =
        HsmVerifier::verify_init(verify_algo, pub_key).expect("verify_init should succeed");

    for chunk in wrong_chunks {
        ctx.update(chunk).expect("update should succeed");
    }

    let result = ctx.finish(&sig);

    assert!(
        matches!(result, Ok(false)),
        "empty-input signature should not verify non-empty chunks, got {:?}",
        result
    );
}
