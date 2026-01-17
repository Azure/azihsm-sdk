// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;

use super::*;

fn get_rsa_unwrapping_key_pair(session: &HsmSession) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();

    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate unwrapping key");

    (priv_key, pub_key)
}

fn import_rsa_key(
    session: &HsmSession,
    der: &[u8],
    bits: u32,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let hash_algo = HsmHashAlgo::Sha384;
    let kek_size = 32;

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, kek_size);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, der)
        .expect("Failed to wrap AES Key");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(hash_algo);
    let (priv_key, pub_key) = unwrap_algo
        .unwrap_key_pair(
            &unwrapping_priv_key,
            &wrapped_key,
            priv_key_props,
            pub_key_props,
        )
        .expect("Failed to unwrap RSA AES key pair");

    (priv_key, pub_key)
}

#[session_test]
fn test_rsa_2048_pkcs1_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let mut hash_algo = HsmHashAlgo::Sha256;
    let message = b"Hello, RSA 2048!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_rsa_3072_pkcs1_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let mut hash_algo = HsmHashAlgo::Sha384;
    let message = b"Hello, RSA 3072!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_rsa_4096_pkcs1_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let mut hash_algo = HsmHashAlgo::Sha512;
    let message = b"Hello, RSA 4096!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pkcs1_padding(hash_algo);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_rsa_2048_pss_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 2048);

    let mut hash_algo = HsmHashAlgo::Sha256;
    let message = b"Hello, RSA 2048!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_rsa_3072_pss_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 3072);

    let mut hash_algo = HsmHashAlgo::Sha384;
    let message = b"Hello, RSA 3072!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}

#[session_test]
fn test_rsa_4096_pss_sign_verify(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");
    let (priv_key, pub_key) = import_rsa_key(&session, &der, 4096);

    let mut hash_algo = HsmHashAlgo::Sha512;
    let message = b"Hello, RSA 4096!";
    let hash =
        HsmHasher::hash_vec(&session, &mut hash_algo, message).expect("Failed to hash message");
    let mut algo = HsmRsaSignAlgo::with_pss_padding(hash_algo, 32);

    let signature = HsmSigner::sign_vec(&mut algo, &priv_key, &hash).expect("Failed to sign data");

    let is_valid = HsmVerifier::verify(&mut algo, &pub_key, &hash, &signature)
        .expect("Failed to verify signature");

    assert!(is_valid, "Signature verification failed");
}
