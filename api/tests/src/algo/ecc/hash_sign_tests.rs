// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

fn generate_ecc_key_pair(
    session: &HsmSession,
    curve: HsmEccCurve,
) -> (HsmEccPrivateKey, HsmEccPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmEccKeyGenAlgo::default();

    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate ECC key pair")
}

fn sign_data(priv_key: &HsmEccPrivateKey, hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmHashSignAlgo::new(hash_algo);
    HsmSigner::sign_vec(&mut sign_algo, priv_key, data).expect("Signature generation failed")
}

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

#[session_test]
fn test_ecc_sign_verify_p256_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_ecc_sign_verify_p384_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P384);
    let data = b"Test data for ECC signing with P-384";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha384, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha384, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_ecc_sign_verify_p521_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P521);
    let data = b"Test data for ECC signing with P-521";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha512, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha512, data, &sig);

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_ecc_sign_verify_invalid_signature(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";

    let mut sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    sig[0] ^= 0xFF;

    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, data, &sig);

    assert!(!is_valid, "Signature verification should have failed");
}

#[session_test]
fn test_ecc_sign_verify_wrong_data(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";
    let wrong_data = b"Different test data";

    let sig = sign_data(&priv_key, HsmHashAlgo::Sha256, data);
    let is_valid = verify_signature(&pub_key, HsmHashAlgo::Sha256, wrong_data, &sig);

    assert!(!is_valid, "Signature verification should have failed");
}

#[session_test]
fn test_ecc_streaming_sign_verify_p256_hash(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data_chunks = [b"Test data " as &[u8], b"for streaming ", b"ECC signing"];

    let sig = streaming_sign_data(priv_key, HsmHashAlgo::Sha256, &data_chunks);
    let is_valid = streaming_verify_signature(pub_key, HsmHashAlgo::Sha256, &data_chunks, &sig);

    assert!(is_valid, "Streaming signature verification failed");
}

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
