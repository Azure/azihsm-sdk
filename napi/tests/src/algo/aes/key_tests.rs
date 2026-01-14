// Copyright (C) Microsoft Corporation. All rights reserved.

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

/// Test AES key generation.
///
/// Verifies that an AES-256  key can be successfully generated within
/// an HSM session with encrypt and decrypt capabilities.
#[session_test]
fn test_token_aes_key_generation(session: HsmSession) {
    // Create key properties for a 256-bit AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES key");

    // Clean up: delete the key from the HSM
    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

#[session_test]
fn test_session_aes_128_key_generation(session: HsmSession) {
    // Create key properties for a 256-bit AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(128)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES key");

    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

#[session_test]
fn test_session_aes_192_key_generation(session: HsmSession) {
    // Create key properties for a 256-bit AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(192)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES key");

    // Clean up: delete the key from the HSM
    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

#[session_test]
fn test_session_aes_256_key_generation(session: HsmSession) {
    // Create key properties for a 256-bit AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES key");

    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

#[session_test]
fn test_aes_128_key_unwrap(session: HsmSession) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 16);
    let aes_key_data = vec![0u8; 16]; // 128-bit AES key
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &aes_key_data)
        .expect("Failed to wrap AES Key");

    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(128)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let aes_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        key_props,
    )
    .expect("Failed to unwrap AES Key");

    HsmKeyManager::delete_key(aes_key).expect("Failed to delete unwrapped AES key");
}

#[session_test]
fn test_aes_192_key_unwrap(session: HsmSession) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 24);
    let aes_key_data = vec![0u8; 24]; // 192-bit AES key
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &aes_key_data)
        .expect("Failed to wrap AES Key");

    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(192)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let aes_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        key_props,
    )
    .expect("Failed to unwrap AES Key");

    HsmKeyManager::delete_key(aes_key).expect("Failed to delete unwrapped AES key");
}

#[session_test]
fn test_aes_256_key_unwrap(session: HsmSession) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let aes_key_data = vec![0u8; 32]; // 256-bit AES key
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &aes_key_data)
        .expect("Failed to wrap AES Key");

    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let aes_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        key_props,
    )
    .expect("Failed to unwrap AES Key");

    HsmKeyManager::delete_key(aes_key).expect("Failed to delete unwrapped AES key");
}
