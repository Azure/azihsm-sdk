// Copyright (C) Microsoft Corporation. All rights reserved.

use super::hmac_tests::*;
use super::*;

fn derive_base_secret_for_hkdf(session: &HsmSession, curve: HsmEccCurve) -> HsmGenericSecretKey {
    let (shared_secret_a, _shared_secret_b) = derive_ecdh_shared_secrets(session, curve);
    shared_secret_a
}

fn derive_hmac_key_with_props(
    session: &HsmSession,
    base_secret: &HsmGenericSecretKey,
    hkdf_hash: HsmHashAlgo,
    props: HsmKeyProps,
) -> Result<HsmHmacKey, HsmError> {
    let mut hkdf_algo = HsmHkdfAlgo::new(hkdf_hash, None, None).expect("HKDF algo creation failed");
    let derived_key = HsmKeyManager::derive_key(session, &mut hkdf_algo, base_secret, props)?;
    derived_key.try_into()
}

/// HMAC derived key must be a secret key.
#[session_test]
fn test_hmac_derived_key_prop_class_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key must have an HMAC key kind.
#[session_test]
fn test_hmac_derived_key_prop_kind_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key must not carry ECC curve metadata.
#[session_test]
fn test_hmac_derived_key_prop_ecc_curve_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key must have a non-zero bit length.
#[session_test]
fn test_hmac_derived_key_prop_bits_zero_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(0)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key must not request unsupported usage flags (e.g. ENCRYPT).
#[session_test]
fn test_hmac_derived_key_prop_encrypt_flag_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_encrypt(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key must not request unsupported usage flags (e.g. DERIVE).
#[session_test]
fn test_hmac_derived_key_prop_derive_flag_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let invalid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_derive(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let result =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, invalid_props);
    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// SESSION lifetime flag is allowed for derived HMAC keys.
#[session_test]
fn test_hmac_derived_key_prop_session_flag_allowed(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let valid_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .is_session(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .expect("Failed to build HMAC key props");

    let derived =
        derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, valid_props)
            .expect("Expected HKDF-derived HMAC key to succeed");
    assert!(derived.is_session());
}

/// Valid HMAC key props should succeed across all supported HMAC kinds.
#[session_test]
fn test_hmac_derived_key_prop_valid_kinds_succeed(session: HsmSession) {
    for (key_kind, bits) in [
        (HsmKeyKind::HmacSha256, 256),
        (HsmKeyKind::HmacSha384, 384),
        (HsmKeyKind::HmacSha512, 512),
    ] {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let base_secret = derive_base_secret_for_hkdf(&session, curve);

        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(key_kind)
            .bits(bits)
            .can_sign(true)
            .can_verify(true)
            .build()
            .expect("Failed to build HMAC key props");

        let _derived = derive_hmac_key_with_props(&session, &base_secret, hkdf_hash, props)
            .expect("Expected HKDF-derived HMAC key to succeed");
    }
}
