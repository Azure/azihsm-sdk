// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;

use super::key_tests::*;

// Helper to generate an ECC key pair using the provided private/public key properties.
fn gen_ecc_key_pair(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmEccPrivateKey, HsmEccPublicKey), HsmError> {
    let mut algo = HsmEccKeyGenAlgo::default();
    HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
}

// Helper to attempt ECC key pair unwrap with given properties, using a bogus blob to exercise validation and DDI paths.
fn unwrap_ecc_with_props(
    session: &HsmSession,
    priv_key_props: HsmKeyProps,
    pub_key_props: HsmKeyProps,
) -> Result<(HsmEccPrivateKey, HsmEccPublicKey), HsmError> {
    let (unwrapping_priv_key, _unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);
    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

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

// Generates a valid ECC sign/verify key pair and expects keygen to succeed.
#[session_test]
fn test_ecc_key_pair_valid_sign_verify_succeeds(session: HsmSession) {
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

    let (_priv_key, _pub_key) =
        gen_ecc_key_pair(&session, priv_key_props, pub_key_props).expect("Keygen should succeed");
}

// Rejects ECC private key props when class is not Private.
#[session_test]
fn test_ecc_priv_props_invalid_class_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
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

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when key kind is not Ecc.
#[session_test]
fn test_ecc_priv_props_invalid_kind_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
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

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when curve is missing (even if bits is set).
#[session_test]
fn test_ecc_priv_props_missing_curve_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .can_sign(true)
        .bits(256)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when both SIGN and DERIVE are set.
#[session_test]
fn test_ecc_priv_props_sign_and_derive_both_set_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC private key props when no usage flags are set.
#[session_test]
fn test_ecc_priv_props_no_usage_flags_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC public key props that include DERIVE usage.
#[session_test]
fn test_ecc_pub_props_derive_rejected(session: HsmSession) {
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
        .can_derive(true)
        .build()
        .expect("Failed to build public key props");

    let result = gen_ecc_key_pair(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap fails fast when private key props are invalid.
#[session_test]
fn test_ecc_unwrap_invalid_priv_props_fails(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
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

    let result = unwrap_ecc_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap validates props first and reaches the DDI layer with valid props.
#[session_test]
fn test_ecc_unwrap_valid_props(session: HsmSession) {
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

    // With a bogus wrapped blob we expect the call to reach the DDI layer and fail there.
    let result = unwrap_ecc_with_props(&session, priv_key_props, pub_key_props);
    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure) | Err(HsmError::InvalidArgument)
    ));
}

// Rejects ECC public key props when class is not Public.
#[session_test]
fn test_ecc_pub_props_invalid_class_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC public key props when key kind is not Ecc.
#[session_test]
fn test_ecc_pub_props_invalid_kind_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa) // invalid
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects ECC public key props when curve is missing (builder-level validation).
#[session_test]
fn test_ecc_pub_props_missing_curve_fails(_session: HsmSession) {
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .can_verify(true)
        .build();

    // Builder should fail before reaching keygen
    assert!(matches!(pub_props, Err(HsmError::PropertyNotPresent)));
}

// Rejects ECC public key props when no usage flags are set.
#[session_test]
fn test_ecc_pub_props_no_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects keygen when private/public curves mismatch.
#[session_test]
fn test_ecc_key_pair_curve_mismatch_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384) // mismatch
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects keygen when usage flags mismatch (sign without verify).
#[session_test]
fn test_ecc_key_pair_usage_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        // missing can_verify
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects derive-only ECC key pair generation (unsupported usage).
#[session_test]
fn test_ecc_key_pair_derive_only_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, false, true); // derive only
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false); // verify

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
// Rejects ECC private key props when bits conflict with curve.
#[session_test]
fn test_ecc_priv_props_bits_curve_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(384) // mismatch
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap fails when public key props are invalid.
#[session_test]
fn test_ecc_unwrap_invalid_pub_props_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures keygen works across multiple ECC curves.
#[session_test]
fn test_ecc_key_pair_multiple_curves_succeed(session: HsmSession) {
    for curve in [HsmEccCurve::P256, HsmEccCurve::P384, HsmEccCurve::P521] {
        let priv_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Private)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(curve)
            .can_sign(true)
            .build()
            .unwrap();

        let pub_props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Public)
            .key_kind(HsmKeyKind::Ecc)
            .ecc_curve(curve)
            .can_verify(true)
            .build()
            .unwrap();

        gen_ecc_key_pair(&session, priv_props, pub_props)
            .expect("Keygen should succeed for all curves");
    }
}

// Rejects derive private with verify public (invalid usage pairing).
#[session_test]
fn test_ecc_key_pair_derive_private_verify_public_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Rejects sign private with derive public.
#[session_test]
fn test_ecc_key_pair_sign_private_derive_public_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Accepts ECC private key props when bits match curve.
#[session_test]
fn test_ecc_priv_props_bits_matches_curve_succeeds(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(256) // Bits must match curve size
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    gen_ecc_key_pair(&session, priv_props, pub_props)
        .expect("Matching bits + curve should succeed");
}

// Rejects public key with multiple usage flags.
#[session_test]
fn test_ecc_pub_props_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .can_derive(true) //
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures private cannot have multiple usage flags even if both are individually valid.
#[session_test]
fn test_ecc_priv_props_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects mismatched curve between private and public keys.
#[session_test]
fn test_ecc_unwrap_curve_mismatch_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384) // mismatch
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects missing public usage flags.
#[session_test]
fn test_ecc_unwrap_usage_mismatch_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() // missing verify
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap does NOT reject bits/curve mismatch at validation layer,
// and instead fails in DDI (since blob is bogus).
#[session_test]
fn test_ecc_unwrap_bits_curve_mismatch_fails(session: HsmSession) {
    let priv_prop = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(384) // mismatch
        .can_sign(true)
        .build()
        .unwrap();

    let pub_prop = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_prop, pub_prop);

    // unwrap does not validate bits vs curve → reaches DDI
    assert!(matches!(
        result,
        Err(HsmError::DdiCmdFailure) | Err(HsmError::InvalidArgument)
    ));
}

// Ensures unwrap rejects derive private + verify public combination.
#[session_test]
fn test_ecc_unwrap_derive_private_verify_public_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true) //
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects invalid public key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_invalid_pub_kind_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects invalid private key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_invalid_priv_kind_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects private key with no usage flags.
#[session_test]
fn test_ecc_unwrap_priv_no_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() //
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects public key with multiple usage flags.
#[session_test]
fn test_ecc_unwrap_pub_multiple_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .can_derive(true)
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects public key with no usage flags.
#[session_test]
fn test_ecc_unwrap_pub_no_usage_flags_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .build() //
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects private key with multiple usage flags.
#[session_test]
fn test_ecc_unwrap_priv_multiple_usage_flags_fails(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_derive(true) // both set
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures ECC public key bits/curve mismatch is not validated and reaches DDI.
#[session_test]
fn test_ecc_pub_props_bits_curve_mismatch_reaches_ddi(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .bits(384) // mismatch
        .can_verify(true)
        .build()
        .unwrap();

    let result = gen_ecc_key_pair(&session, priv_props, pub_props);

    // Public bits mismatch is NOT validated → should NOT be InvalidKeyProps
    assert!(!matches!(result, Err(HsmError::InvalidKeyProps)));
}

// Ensures unwrap rejects private key props with missing curve.
#[session_test]
fn test_ecc_unwrap_priv_missing_curve_fails(_session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .can_sign(true)
        .build();
    assert!(priv_props.is_err());
}

// Ensures unwrap rejects public key props with missing curve.
#[session_test]
fn test_ecc_unwrap_pub_missing_curve_fails(_session: HsmSession) {
    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .can_verify(true)
        .build();

    assert!(pub_props.is_err());
}

// Ensures unwrap rejects sign private + derive public combination.
#[session_test]
fn test_ecc_unwrap_sign_private_derive_public_fails(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false); // sign = true

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true) //  invalid with sign private
        .build()
        .unwrap();

    let result = unwrap_ecc_with_props(&session, priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
