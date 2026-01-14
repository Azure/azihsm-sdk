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
        .can_verify(true)
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

fn hash_data(session: &HsmSession, mut hash_algo: HsmHashAlgo, data: &[u8]) -> Vec<u8> {
    HsmHasher::hash_vec(session, &mut hash_algo, data).expect("Failed to hash data")
}

fn sign_hash(priv_key: &HsmEccPrivateKey, hash: &[u8]) -> Vec<u8> {
    let mut sign_algo = HsmEccSignAlgo::default();
    HsmSigner::sign_vec(&mut sign_algo, priv_key, hash).expect("Signature generation failed")
}

fn verify_hash_signature(pub_key: &HsmEccPublicKey, hash: &[u8], signature: &[u8]) -> bool {
    let mut verify_algo = HsmEccSignAlgo::default();
    verify_algo
        .verify(pub_key, hash, signature)
        .expect("Failed to verify signature")
}

#[session_test]
fn test_ecc_sign_verify_p256(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P256);
    let data = b"Test data for ECC signing";

    let hash = hash_data(&session, HsmHashAlgo::Sha256, data);
    let sig = sign_hash(&priv_key, &hash);
    let is_valid = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_ecc_sign_verify_p384(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P384);
    let data = b"Test data for ECC signing";

    let hash = hash_data(&session, HsmHashAlgo::Sha384, data);
    let sig = sign_hash(&priv_key, &hash);
    let is_valid = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_ecc_sign_verify_p521(session: HsmSession) {
    let (priv_key, pub_key) = generate_ecc_key_pair(&session, HsmEccCurve::P521);
    let data = b"Test data for ECC signing";

    let hash = hash_data(&session, HsmHashAlgo::Sha512, data);
    let sig = sign_hash(&priv_key, &hash);
    let is_valid = verify_hash_signature(&pub_key, &hash, &sig);

    assert!(is_valid, "Signature verification failed");
}
