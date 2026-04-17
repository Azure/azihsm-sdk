// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

use super::key_tests::*;

// ================================
// Helper functions
// ================================

/// Helper to generate an RSA unwrapping key pair with given key properties.
fn gen_rsa_unwrapping_key_pair(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmRsaPrivateKey, HsmRsaPublicKey), HsmError> {
    let mut algo = HsmRsaKeyUnwrappingKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
}

/// Helper to invoke RSA unwrap using provided key properties and return the result.
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

/// Helper to assert RSA keygen fails for unsupported bits.
fn rsa_keygen_should_fail(session: &HsmSession, bits: u32) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Helper to run RSA keygen and assert expected outcome.
fn rsa_keygen_expect(session: &HsmSession, bits: u32, should_succeed: bool) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(session, priv_key_props, pub_key_props);

    if should_succeed {
        if let Err(e) = result {
            panic!("RSA {}-bit expected success but got {:?}", bits, e);
        }
    } else {
        match result {
            Ok(_) => panic!("RSA {}-bit expected failure but got success", bits),
            Err(e) => assert!(
                matches!(e, HsmError::InvalidKeyProps),
                "RSA {}-bit expected InvalidKeyProps but got {:?}",
                bits,
                e
            ),
        }
    }
}

// ============================================================
// test case section
// ============================================================

// Generates a valid RSA unwrapping key pair and expects keygen to succeed.
#[session_test]
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

// Rejects RSA unwrapping keygen when private key class is not Private.
#[session_test]
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

// Rejects RSA unwrapping keygen when public key class is not Public.
#[session_test]
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

// Rejects RSA unwrapping keygen when key kind is not RSA.
#[session_test]
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

// Rejects RSA unwrapping keygen when props include an ECC curve.
#[session_test]
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

// Rejects RSA private key props when multiple usage flags are set.
#[session_test]
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

// Rejects RSA unwrap when public key props include an unsupported usage flag.
#[session_test]
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

// Ensures unwrap validates props first and reaches the DDI layer with valid props.
#[session_test]
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
    assert!(
        matches!(result, Err(HsmError::DdiCmdFailure)),
        "Expected unwrap to reach DDI and fail there"
    );
}

// Rejects RSA keygen when private and public key sizes mismatch.
#[session_test]
fn test_rsa_keygen_mismatched_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public key kinds mismatch.
#[session_test]
fn test_rsa_keygen_mismatched_key_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when private key has no usage flag.
#[session_test]
fn test_rsa_unwrap_priv_missing_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when public key has no usage flag.
#[session_test]
fn test_rsa_unwrap_pub_missing_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when private key has wrong usage flag.
#[session_test]
fn test_rsa_priv_wrong_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true) // wrong usage
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key has wrong usage flag.
#[session_test]
fn test_rsa_pub_wrong_usage_flag_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true) // wrong usage
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when key size is zero.
#[session_test]
fn test_rsa_keygen_zero_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(0)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(0)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private key props are missing key kind.
#[session_test]
fn test_rsa_keygen_missing_key_kind_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .bits(2048)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// Rejects RSA key props when bits are missing.
#[session_test]
fn test_rsa_keygen_missing_bits_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// Rejects RSA key props when class is missing.
#[session_test]
fn test_rsa_keygen_missing_class_fails(_session: HsmSession) {
    let result = HsmKeyPropsBuilder::default()
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build();

    assert!(result.is_err());
}

// RSA keygen rejects unsupported 1024-bit keys.
#[session_test]
fn test_rsa_keygen_1024_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 1024);
}

// RSA keygen rejects unsupported 3072-bit keys.
#[session_test]
fn test_rsa_keygen_3072_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 3072);
}

// RSA keygen rejects unsupported 4096-bit keys.
#[session_test]
fn test_rsa_keygen_4096_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 4096);
}

// Generates a valid 2048-bit RSA key pair and expects success.
#[session_test]
fn test_rsa_keygen_2048_succeeds(session: HsmSession) {
    rsa_keygen_expect(&session, 2048, true);
}

// Rejects RSA keygen when bits are just below supported boundary.
#[session_test]
fn test_rsa_keygen_2047_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 2047);
}

// Rejects RSA keygen when bits are just above supported boundary.
#[session_test]
fn test_rsa_keygen_2049_fails(session: HsmSession) {
    rsa_keygen_should_fail(&session, 2049);
}

// RSA keygen rejects sign/verify usage for unwrapping algo.
#[session_test]
fn test_rsa_keygen_sign_verify_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// RSA rejects ECC curve in props.
#[session_test]
fn test_rsa_with_ecc_curve_in_pub_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256) // invalid
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private key has both wrap and unwrap usage.
#[session_test]
fn test_rsa_priv_wrap_and_unwrap_conflict_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when both private and public keys lack usage flags.
#[session_test]
fn test_rsa_both_missing_usage_flags_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA key props when ECC curve is provided on both keys.
#[session_test]
fn test_rsa_both_with_ecc_curve_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .ecc_curve(HsmEccCurve::P256)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public classes are swapped.
#[session_test]
fn test_rsa_keygen_swapped_classes_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public) // swapped
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // swapped
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when key kind is AES.
#[session_test]
fn test_rsa_keygen_with_aes_key_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes) // invalid
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes) // invalid
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA keygen when private/public key kinds are AES/RSA mixed.
#[session_test]
fn test_rsa_keygen_mixed_aes_rsa_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes)
        .bits(2048)
        .can_unwrap(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = gen_rsa_unwrapping_key_pair(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key has multiple usage flags.
#[session_test]
fn test_rsa_pub_multiple_usage_flags_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .can_wrap(true) // multiple usage
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects RSA unwrap when public key class is not Public.
#[session_test]
fn test_rsa_unwrap_invalid_pub_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when usage pair is logically incompatible.
#[session_test]
fn test_rsa_usage_pair_mismatch_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true) // wrong pairing
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects unwrap when private/public bits mismatch.
#[session_test]
fn test_rsa_unwrap_mismatched_bits_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(4096)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// Ensures exactly one usage flag is required.
#[session_test]
fn test_rsa_exactly_one_usage_required(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true)
        .can_decrypt(true) // extra
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when private key has can_wrap only.
#[session_test]
fn test_rsa_priv_can_wrap_only_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_wrap(true) // invalid
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Rejects RSA unwrap when public key has can_unwrap usage.
#[session_test]
fn test_rsa_pub_can_unwrap_rejected(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_unwrap(true) // invalid
        .build()
        .unwrap();

    let result = unwrap_rsa_with_props(&session, priv_key_props, pub_key_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
