// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_napi::*;
use azihsm_napi_tests_macro::*;

use super::key_tests::*;

fn gen_rsa_unwrapping_key_pair(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
}

fn unwrap_rsa_with_props(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let (unwrapping_priv_key, _unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    // Deliberately invalid wrapped blob; unwrap should fail *before* DDI on invalid props.
    let bogus_wrapped_key: &[u8] = &[];

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        bogus_wrapped_key,
        priv_key_props,
        pub_key_props,
    )
}

#[session_test]
// Generates a valid RSA unwrapping key pair and expects keygen to succeed.
fn test_rsa_unwrapping_key_pair_valid_props_succeeds(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let (_priv_key, _pub_key) =
        gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props)
            .expect("RSA unwrapping keygen should succeed");
}

#[session_test]
// Rejects RSA unwrapping keygen when private key class is not Private.
fn test_rsa_unwrapping_keygen_invalid_priv_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA unwrapping keygen when public key class is not Public.
fn test_rsa_unwrapping_keygen_invalid_pub_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA unwrapping keygen when key kind is not RSA.
fn test_rsa_unwrapping_keygen_invalid_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA unwrapping keygen when RSA key size is unsupported.
fn test_rsa_unwrapping_keygen_invalid_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(1024)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(1024)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA unwrapping keygen when props include an ECC curve.
fn test_rsa_unwrapping_keygen_ecc_curve_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_unwrap(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA private key props when multiple usage flags are set.
fn test_rsa_priv_props_multiple_usage_flags_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Rejects RSA unwrap when public key props include an unsupported usage flag.
fn test_rsa_pub_props_unsupported_usage_flag_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build public key props");

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

#[session_test]
// Ensures unwrap validates props first and reaches the DDI layer with valid props.
fn test_rsa_unwrap_valid_props_reaches_ddi(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    // With a bogus wrapped blob we expect the call to reach the DDI layer and fail there.
    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure) | Err(HsmError::InvalidArgument)
    ));
}
