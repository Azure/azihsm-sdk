// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

/// Test AES key property validation. Reject AES keys with non-secret key class.
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

/// Test AES key property validation rejects non-AES key kinds.
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

/// Reject AES keys that incorrectly include ECC curve metadata.
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

/// Reject AES keys with SIGN capability.
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

/// Reject AES keys with VERIFY capability.
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

/// Reject AES keys with DERIVE capability.
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

/// Reject AES keys marked as UNWRAP capable.
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

/// Reject AES keys marked as WRAP capable.
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

/// Ensure valid AES key sizes (128/192/256) succeed.
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

/// Ensure invalid AES key sizes are rejected.
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

/// Reject unwrap when key class is invalid before reaching DDI.
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

/// Reject unwrap when key kind is not AES.
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

/// Reject unwrap when SIGN flag is present.
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

/// Reject unwrap when VERIFY flag is present.
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

/// Reject unwrap when WRAP capability is present.
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

/// Reject unwrap when AES key size is invalid.
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

/// Builder must fail if key class is missing.
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

/// Builder must fail if key kind is missing.
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

/// Builder must fail if key size is not specified.
#[test]
fn test_aes_key_props_builder_missing_bits_fails() {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .build();

    assert!(matches!(result, Err(HsmError::PropertyNotPresent)));
}

/// AES non-session key generation should succeed.
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

/// Reject AES-XTS keys with invalid class.
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

/// Reject AES-XTS keys with incorrect key kind.
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

/// AES-XTS requires both encrypt and decrypt flags.
#[session_test]
fn test_aes_xts_key_prop_requires_encrypt_and_decrypt(session: HsmSession) {
    for (can_encrypt, can_decrypt) in [(false, false), (true, false), (false, true)] {
        let invalid_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(512)
            .can_encrypt(can_encrypt)
            .can_decrypt(can_decrypt)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
        assert!(
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "XTS key generation should reject can_encrypt={can_encrypt} can_decrypt={can_decrypt}"
        );
    }
}

/// AES-XTS key generation should succeed for 512-bit keys.
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

/// Reject invalid AES-XTS key sizes.
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

/// Reject unsupported usage flags for AES-XTS keys.
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

/// Reject unwrap when ECC metadata is present.
#[session_test]
fn test_aes_unwrap_invalid_props_ecc_curve_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject unwrap when DERIVE capability is present.
#[session_test]
fn test_aes_unwrap_invalid_props_derive_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject unwrap when UNWRAP flag is present.
#[session_test]
fn test_aes_unwrap_invalid_props_unwrap_flag_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_unwrap(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES key generation when no usage flags are set.
#[session_test]
fn test_aes_key_prop_no_usage_flags_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, props);

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "AES key generation should fail when no usage flags are set"
    );
}

/// Reject AES-XTS keys with ECC metadata.
#[session_test]
fn test_aes_xts_key_prop_ecc_curve_rejected(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .ecc_curve(HsmEccCurve::P256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES-XTS keys with DERIVE capability.
#[session_test]
fn test_aes_xts_key_prop_derive_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_derive(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES-XTS keys with VERIFY capability.
#[session_test]
fn test_aes_xts_key_prop_verify_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_verify(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys with both SIGN and VERIFY flags.
#[session_test]
fn test_aes_key_prop_sign_and_verify_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys combining DERIVE with encrypt/decrypt usage.
#[session_test]
fn test_aes_key_prop_derive_with_encrypt_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_derive(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys with both WRAP and UNWRAP capabilities.
#[session_test]
fn test_aes_key_prop_wrap_and_unwrap_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_wrap(true)
        .can_unwrap(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys combining ECC metadata with SIGN flag.
#[session_test]
fn test_aes_key_prop_ecc_and_sign_validation(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys with all invalid usage flags enabled.
#[session_test]
fn test_aes_key_prop_all_invalid_flags(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .can_derive(true)
        .can_wrap(true)
        .can_unwrap(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject unwrap when both WRAP and UNWRAP flags are set.
#[session_test]
fn test_aes_unwrap_invalid_props_wrap_and_unwrap_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_wrap(true)
        .can_unwrap(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject unwrap when both SIGN and VERIFY flags are set.
#[session_test]
fn test_aes_unwrap_invalid_props_sign_and_verify_fails_fast(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Builder should fail when ECC curve is provided without key kind.
#[test]
fn test_aes_key_props_builder_ecc_curve_without_kind_fails() {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .build();

    assert!(matches!(result, Err(HsmError::KeyKindNotSpecified)));
}

/// Reject AES-XTS keys with WRAP capability.
#[session_test]
fn test_aes_xts_key_prop_wrap_rejected(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_wrap(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES-XTS keys with UNWRAP capability.
#[session_test]
fn test_aes_xts_key_prop_unwrap_rejected(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_unwrap(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// AES session key generation should succeed.
#[session_test]
fn test_aes_key_gen_session_key_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .is_session(true)
        .key_kind(HsmKeyKind::Aes)
        .bits(128)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key =
        test_aes_key_prop_gen_key(&session, props).expect("AES session key generation failed");

    assert!(
        key.is_session(),
        "Generated AES key should be a session key"
    );
}

/// Reject AES keys with encrypt-only usage.
#[session_test]
fn test_aes_key_prop_encrypt_only_rejected(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject encrypt-only usage"
    );
}

/// Reject AES keys with decrypt-only usage.
#[session_test]
fn test_aes_key_prop_decrypt_only_rejected(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject decrypt-only usage"
    );
}

/// AES-XTS session key generation should succeed.
#[session_test]
fn test_aes_xts_key_gen_session_key_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .is_session(true)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key = test_aes_xts_key_prop_gen_key(&session, props)
        .expect("AES-XTS session key generation failed");

    assert!(key.is_session());
}

/// AES-XTS non-session key generation should succeed.
#[session_test]
fn test_aes_xts_key_gen_non_session_succeeds(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .is_session(false)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key =
        test_aes_xts_key_prop_gen_key(&session, props).expect("AES-XTS key generation failed");

    assert!(!key.is_session());
}

/// Reject AES-XTS keys with private key class.
#[session_test]
fn test_aes_xts_key_prop_private_class_rejected(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES keys that only specify ECC metadata.
#[session_test]
fn test_aes_key_prop_ecc_curve_only_rejected(session: HsmSession) {
    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, invalid_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Reject AES key sizes near valid boundaries.
#[session_test]
fn test_aes_key_prop_near_boundary_sizes_rejected(session: HsmSession) {
    for bits in [127u32, 129, 191, 193] {
        let invalid_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_key_prop_gen_key(&session, invalid_props);

        assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
    }
}

/// Ensure valid unwrap props reach the unwrap implementation.
#[session_test]
fn test_aes_unwrap_valid_props_reaches_ddi(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let result = test_aes_unwrap_with_props(&session, key_props);

    assert!(
        !matches!(result, Err(HsmError::InvalidKeyProps)),
        "Valid props should reach unwrap logic"
    );
}

/// Verify generated AES key metadata matches requested properties.
#[session_test]
fn test_aes_key_gen_metadata_validation(session: HsmSession) {
    for &bits in AES_VALID_KEY_SIZES_IN_BITS.iter() {
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let key = test_aes_key_prop_gen_key(&session, props).expect("AES key generation failed");

        assert_eq!(key.kind(), HsmKeyKind::Aes);
        assert_eq!(key.class(), HsmKeyClass::Secret);
        assert_eq!(key.bits(), bits);
    }
}

/// Validate AES-XTS key size handling across multiple sizes.
#[session_test]
fn test_aes_xts_key_prop_all_sizes_validation(session: HsmSession) {
    for bits in [256u32, 384, 512, 768] {
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .build()
            .expect("Failed to build key props");

        let result = test_aes_xts_key_prop_gen_key(&session, props);

        if bits == 512 {
            assert!(result.is_ok(), "512 should be valid for AES-XTS");
        } else {
            assert!(
                matches!(result, Err(HsmError::InvalidKeyProps)),
                "Invalid AES-XTS key size {bits} should fail"
            );
        }
    }
}

/// Reject AES-XTS keys with no usage flags.
#[session_test]
fn test_aes_xts_key_prop_no_usage_flags_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_xts_key_prop_gen_key(&session, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES-XTS should reject keys with no usage flags"
    );
}

/// Reject AES keys when encrypt and decrypt are both disabled.
#[session_test]
fn test_aes_key_prop_encrypt_and_decrypt_explicitly_false(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(false)
        .can_decrypt(false)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_key_prop_gen_key(&session, props);

    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "Explicitly disabling both encrypt and decrypt should be rejected"
    );
}

/// Builder should allow ECC property even for AES (validated later).
#[test]
fn test_builder_allows_ecc_curve_for_aes_kind() {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .build();

    assert!(
        result.is_ok(),
        "Builder should allow property construction; validation happens later"
    );
}

/// Later builder calls should override earlier usage flags.
#[test]
fn test_builder_duplicate_usage_flag_override() {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_encrypt(false)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    assert_eq!(props.can_encrypt(), false);
}

/// Reject extremely large AES key sizes.
#[session_test]
fn test_aes_key_prop_large_invalid_sizes(session: HsmSession) {
    for bits in [4096u32, 8192, u32::MAX] {
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
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "AES should reject invalid large key size {bits}"
        );
    }
}

/// Reject unwrap attempts with excessively large AES key size.
#[session_test]
fn test_aes_unwrap_invalid_large_key_size(session: HsmSession) {
    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(4096)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let result = test_aes_unwrap_with_props(&session, key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Verify generated AES-XTS key metadata.
#[session_test]
fn test_aes_xts_key_gen_metadata_validation(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let key =
        test_aes_xts_key_prop_gen_key(&session, props).expect("AES-XTS key generation failed");

    assert_eq!(key.kind(), HsmKeyKind::AesXts);
    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.bits(), 512);
}
