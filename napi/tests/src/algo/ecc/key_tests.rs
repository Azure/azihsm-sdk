// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;
use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

pub(crate) fn get_rsa_unwrapping_key_pair(
    session: &HsmSession,
) -> (HsmRsaPrivateKey, HsmRsaPublicKey) {
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

/// Test ECC key pair generation.
///
/// Verifies that an ECC P-256 key pair can be successfully generated within
/// an HSM session with sign and verify capabilities.
#[session_test]
fn test_ecc_p256_key_pair_generation(session: HsmSession) {
    // Create key properties for the private key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build key props");

    // Create key properties for the public key
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build key props");

    // Create the ECC key generation algorithm
    let mut algo = HsmEccKeyGenAlgo::default();

    // Generate the key pair
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    drop(pub_key);

    // Get the public key
    let pub_key = priv_key.public_key();

    // Clean up: delete the key from the HSM
    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_ecc_p384_key_pair_generation(session: HsmSession) {
    // Create key properties for the private key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .build()
        .expect("Failed to build key props");

    // Create key properties for the public key
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_verify(true)
        .build()
        .expect("Failed to build key props");

    // Create the ECC key generation algorithm
    let mut algo = HsmEccKeyGenAlgo::default();
    // Generate the key pair
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_ecc_p521_key_pair_generation(session: HsmSession) {
    // Create key properties for the private key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P521)
        .can_sign(true)
        .build()
        .expect("Failed to build key props");

    // Create key properties for the public key
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P521)
        .can_verify(true)
        .build()
        .expect("Failed to build key props");

    // Create the ECC key generation algorithm
    let mut algo = HsmEccKeyGenAlgo::default();
    // Generate the key pair
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_unwrap_ecc_p256_key(session: HsmSession) {
    use crypto::*;

    let priv_key = crypto::EccPrivateKey::from_curve(EccCurve::P256)
        .expect("Failed to create ECC private key");
    let der = priv_key.to_vec().expect("Failed to export ECC Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha1, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap ECC Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha1);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap ECC Key");

    assert!(priv_key.can_sign(), "Private key cannot sign");
    assert!(pub_key.can_verify(), "Public key cannot verify");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

#[session_test]
fn test_unwrap_ecc_p384_key(session: HsmSession) {
    use crypto::*;
    let priv_key = crypto::EccPrivateKey::from_curve(EccCurve::P384)
        .expect("Failed to create ECC private key");
    let der = priv_key.to_vec().expect("Failed to export ECC Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap ECC Key");
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap ECC Key");

    assert!(priv_key.can_sign(), "Private key cannot sign");
    assert!(pub_key.can_verify(), "Public key cannot verify");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

//implement p521 unwrap test
#[session_test]
fn test_unwrap_ecc_p521_key(session: HsmSession) {
    use crypto::*;
    let priv_key = crypto::EccPrivateKey::from_curve(EccCurve::P521)
        .expect("Failed to create ECC private key");
    let der = priv_key.to_vec().expect("Failed to export ECC Key");
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha512, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap ECC Key");
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P521)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P521)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha512);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap ECC Key");

    assert!(priv_key.can_sign(), "Private key cannot sign");
    assert!(pub_key.can_verify(), "Public key cannot verify");

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}
