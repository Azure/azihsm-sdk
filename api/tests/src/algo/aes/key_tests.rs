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

fn verify_generated_aes_key_properties(key: &HsmAesKey, bits: u32, is_session: bool) {
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), bits, "Key bits mismatch");
    assert!(key.is_local(), "Session key should be local");
    assert_eq!(key.is_session(), is_session, "Session flag mismatch");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");
}

fn verify_unwrapped_aes_key_properties(key: &HsmAesKey, bits: u32, is_session: bool) {
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), bits, "Key bits mismatch");
    assert!(!key.is_local(), "Unwrapped key should not be local");
    assert_eq!(key.is_session(), is_session, "Session flag mismatch");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");
}

fn compare_key_properties(original: &HsmAesKey, unmasked: &HsmAesKey) {
    assert_eq!(original.class(), unmasked.class(), "Key class mismatch");
    assert_eq!(original.kind(), unmasked.kind(), "Key kind mismatch");
    assert_eq!(original.bits(), unmasked.bits(), "Key bits mismatch");
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Decrypt capability mismatch"
    );
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Verify capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Extractable flag mismatch"
    );
}

fn test_session_aes_key_generation_common(session: &HsmSession, bits: u32) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut algo = HsmAesKeyGenAlgo::default();
    let key =
        HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key");

    verify_generated_aes_key_properties(&key, bits, true);
    HsmKeyManager::delete_key(key).expect("Failed to delete AES key");
}

fn test_aes_key_unwrap_common(session: &HsmSession, bits: u32, is_session: bool) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let key_bytes = (bits / 8) as usize;
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);
    let aes_key_data = vec![0u8; key_bytes];
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &aes_key_data)
        .expect("Failed to wrap AES Key");

    let mut builder = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true);

    if is_session {
        builder = builder.is_session(true);
    }

    let key_props = builder.build().expect("Failed to build key props");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let aes_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        key_props,
    )
    .expect("Failed to unwrap AES Key");

    verify_unwrapped_aes_key_properties(&aes_key, bits, is_session);
    HsmKeyManager::delete_key(aes_key).expect("Failed to delete unwrapped AES key");
}

fn test_aes_key_unmask_common(session: &HsmSession, bits: u32) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let original_key = HsmKeyManager::generate_key(session, &mut gen_algo, props)
        .expect("Failed to generate AES key");

    let masked_key = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    let mut unmask_algo = HsmAesKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(session, &mut unmask_algo, &masked_key)
        .expect("Failed to unmask AES key");

    compare_key_properties(&original_key, &unmasked_key);
    HsmKeyManager::delete_key(unmasked_key).expect("Failed to delete unmasked AES key");
    HsmKeyManager::delete_key(original_key).expect("Failed to delete original AES key");
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

    // Verify key properties
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), 256, "Key bits mismatch");
    assert!(key.is_local(), "Token key should be local");
    assert!(!key.is_session(), "Token key should not be a session key");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");

    // Clean up: delete the key from the HSM
    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

#[session_test]
fn test_session_aes_128_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 128);
}

#[session_test]
fn test_session_aes_192_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 192);
}

#[session_test]
fn test_session_aes_256_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 256);
}

#[session_test]
fn test_aes_128_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 128, false);
}

#[session_test]
fn test_aes_192_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 192, false);
}

#[session_test]
fn test_aes_256_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 256, true);
}

#[session_test]
fn test_aes_128_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 128);
}

#[session_test]
fn test_aes_192_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 192);
}

#[session_test]
fn test_aes_256_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 256);
}
