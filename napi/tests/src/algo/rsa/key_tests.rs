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

// implement test case to generate unwrapping key
#[session_test]
fn test_generate_unwrapping_key(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    assert!(priv_key.can_unwrap(), "Private key cannot unwrap");
    assert!(pub_key.can_wrap(), "Public key cannot wrap");
}

#[session_test]
fn test_unwrap_rsa_2048_key(session: HsmSession) {
    use crypto::*;
    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

    assert!(priv_key.can_decrypt(), "Private key cannot decrypt");
    assert!(pub_key.can_encrypt(), "Public key cannot encrypt");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_unwrap_rsa_3072_key(session: HsmSession) {
    use crypto::*;
    let priv_key = crypto::RsaPrivateKey::generate(384).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 24);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_decrypt(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

    assert!(priv_key.can_decrypt(), "Private key cannot decrypt");
    assert!(pub_key.can_encrypt(), "Public key cannot encrypt");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_unwrap_rsa_4096_key(session: HsmSession) {
    use crypto::*;
    let priv_key = crypto::RsaPrivateKey::generate(512).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 16);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(4096)
        .can_decrypt(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(4096)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

    assert!(priv_key.can_decrypt(), "Private key cannot decrypt");
    assert!(pub_key.can_encrypt(), "Public key cannot encrypt");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}
