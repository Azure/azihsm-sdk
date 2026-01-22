// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

const AES_VALID_KEY_SIZES_IN_BITS: [u32; 3] = [128, 192, 256];

// A small set of common invalid sizes to ensure validation rejects them.
const AES_INVALID_KEY_SIZES_IN_BITS: [u32; 10] = [0, 1, 64, 127, 129, 160, 191, 193, 255, 257];

fn test_aes_key_prop_gen_key(
    session: &HsmSession,
    props: HsmKeyProps,
) -> Result<HsmAesKey, HsmError> {
    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props)
}

fn test_aes_xts_key_prop_gen_key(
    session: &HsmSession,
    props: HsmKeyProps,
) -> Result<HsmAesXtsKey, HsmError> {
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props)
}

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
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
        .expect("Failed to generate RSA unwrapping key pair")
}

fn test_aes_unwrap_with_props(
    session: &HsmSession,
    key_props: HsmKeyProps,
) -> Result<HsmAesKey, HsmError> {
    let (unwrapping_priv_key, _unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);
    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    // Deliberately invalid wrapped blob; unwrap should fail *before* DDI on invalid props.
    let bogus_wrapped_key: &[u8] = &[];

    HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        bogus_wrapped_key,
        key_props,
    )
}

/// Test AES key property validation.
#[session_test]
fn test_aes_key_prop_class_validation(session: HsmSession) {
    //build key properties with invalid class for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for non-secret AES keys"
    );
}

#[session_test]
fn test_aes_key_prop_kind_validation(session: HsmSession) {
    //build key properties with invalid kind for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Rsa)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for non-AES keys"
    );
}

#[session_test]
fn test_aes_key_prop_ecc_curve_rejected(session: HsmSession) {
    // ECC curve metadata must not be set for AES keys.
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_key_prop_sign_validation(session: HsmSession) {
    //build key properties with invalid usage flags for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true) // Invalid usage flag for AES key
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");
    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for AES keys with SIGN"
    );
}

#[session_test]
fn test_aes_key_prop_verify_validation(session: HsmSession) {
    // build key properties with invalid usage flags for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_verify(true) // Invalid usage flag for AES key
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for AES keys with VERIFY"
    );
}

#[session_test]
fn test_aes_key_prop_derive_validation(session: HsmSession) {
    // build key properties with invalid usage flags for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true) // Invalid usage flag for AES key
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for AES keys with DERIVE"
    );
}

#[session_test]
fn test_aes_key_prop_unwrap_validation(session: HsmSession) {
    //build key properties with extractable set to true for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_unwrap(true) // Key material must not be unwrappable/extractable
        .build()
        .expect("Failed to build key props");
    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for AES keys with UNWRAP"
    );
}

#[session_test]
fn test_aes_key_prop_wrap_validation(session: HsmSession) {
    //build key properties with extractable set to true for AES key
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(false)
        .can_decrypt(true)
        .can_wrap(true) // Key material must not be unwrappable/extractable
        .build()
        .expect("Failed to build key props");
    let result = test_aes_key_prop_gen_key(&session, invalid_props);
    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "Key generation should fail with InvalidKeyProps for AES keys with WRAP"
    );
}

#[session_test]
fn test_aes_key_prop_size_valid_succeeds(session: HsmSession) {
    for &bits in AES_VALID_KEY_SIZES_IN_BITS.iter() {
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_key_prop_gen_key(&session, props);
        assert!(
            result.is_ok(),
            "Key generation should succeed for valid AES key size {bits}"
        );
    }
}

#[session_test]
fn test_aes_key_prop_size_invalid_fails(session: HsmSession) {
    for &bits in AES_INVALID_KEY_SIZES_IN_BITS.iter() {
        let invalid_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_key_prop_gen_key(&session, invalid_props);
        assert!(
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "Key generation should fail with InvalidKeyProps for invalid AES key size {bits}"
        );
    }
}

/// Ensures AES unwrap validates `key_props` *before* calling into DDI.
///
/// Each test uses a deliberately invalid wrapped blob; the only acceptable error
/// is `InvalidKeyProps` (i.e. fail fast on props validation).
#[session_test]
fn test_aes_unwrap_invalid_props_class_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_unwrap_invalid_props_kind_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Rsa)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_unwrap_invalid_props_sign_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_unwrap_invalid_props_verify_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_verify(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_unwrap_invalid_props_wrap_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_wrap(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_unwrap_invalid_props_key_size_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .is_session(false)
        .key_kind(HsmKeyKind::Aes)
        .bits(257)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[test]
fn test_aes_key_props_builder_missing_class_fails() {
    let result = HsmKeyPropsBuilder::default()
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build();

    assert!(matches!(result, Err(HsmError::KeyClassNotSpecified)));
}

#[test]
fn test_aes_key_props_builder_missing_kind_fails() {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build();

    assert!(matches!(result, Err(HsmError::KeyKindNotSpecified)));
}

#[test]
fn test_aes_key_props_builder_missing_bits_fails() {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .build();

    assert!(matches!(result, Err(HsmError::KeyPropertyNotPresent)));
}

#[session_test]
fn test_aes_key_gen_non_session_succeeds(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .is_session(false)
        .key_kind(HsmKeyKind::Aes)
        .bits(128)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, key_props);
    assert!(
        result.is_ok(),
        "AES key generation should succeed for non-session keys"
    );
    let key = result.unwrap();
    assert!(
        !key.is_session(),
        "Generated key should not be a session key"
    );
}

/// Test AES-XTS key property validation.
#[session_test]
fn test_aes_xts_key_prop_class_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_xts_key_prop_kind_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_xts_key_prop_requires_encrypt_or_decrypt(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(false)
        .can_decrypt(false)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
fn test_aes_xts_key_prop_size_valid_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key = test_aes_xts_key_prop_gen_key(&session, props).expect("XTS key generation failed");
    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.kind(), HsmKeyKind::AesXts);
    assert_eq!(key.bits(), 512);
}

#[session_test]
fn test_aes_xts_key_prop_size_invalid_fails(session: HsmSession) {
    for bits in [0u32, 1, 256, 511, 513, 1024] {
        let invalid_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
        assert!(
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "XTS key generation should reject invalid key size {bits}"
        );
    }
}

#[session_test]
fn test_aes_xts_key_prop_rejects_invalid_usage_flags(session: HsmSession) {
    // A few representative invalid flags; AES-XTS should only allow encrypt/decrypt.
    let invalid_props_list = [
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(512)
            .can_encrypt(true)
            .can_decrypt(true)
            .can_sign(true)
            .build()
            .expect("Failed to build key props"),
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(512)
            .can_encrypt(true)
            .can_decrypt(true)
            .can_wrap(true)
            .build()
            .expect("Failed to build key props"),
        HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(512)
            .ecc_curve(HsmEccCurve::P256)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props"),
    ];

    for invalid_props in invalid_props_list {
        let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
        assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
    }
}

#[session_test]
fn test_aes_xts_key_prop_encrypt_only_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(false)
        .build()
        .expect("Failed to build key props");

    let key = test_aes_xts_key_prop_gen_key(&session, props).expect("XTS key generation failed");
    assert!(key.can_encrypt());
    assert!(!key.can_decrypt());
}

#[session_test]
fn test_aes_xts_key_prop_decrypt_only_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(false)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key = test_aes_xts_key_prop_gen_key(&session, props).expect("XTS key generation failed");
    assert!(!key.can_encrypt());
    assert!(key.can_decrypt());
}
