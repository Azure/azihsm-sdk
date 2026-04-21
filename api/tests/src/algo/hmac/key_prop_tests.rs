// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::hmac_tests::*;
use super::*;

// ================================
// Helpers
// ================================

/// Derive a base ECDH shared secret to be used as HKDF input.
fn derive_base_secret_for_hkdf(session: &HsmSession, curve: HsmEccCurve) -> HsmGenericSecretKey {
    let (shared_secret_a, _shared_secret_b) = derive_ecdh_shared_secrets(session, curve);
    shared_secret_a
}

/// Derive an HMAC key using HKDF with the given properties.
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

// ============================================================
// test case section
// ============================================================

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

/// HMAC must require at least sign capability
#[session_test]
fn test_hmac_derived_key_prop_missing_sign_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_verify(true) // missing sign
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// HMAC must require verify capability
#[session_test]
fn test_hmac_derived_key_prop_missing_verify_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true) // missing verify
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// HMAC key bits must match hash size
#[session_test]
fn test_hmac_derived_key_prop_invalid_bits_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(128) // invalid
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// HMAC must reject wrap/unwrap/decrypt flags
#[session_test]
fn test_hmac_derived_key_prop_other_flags_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_wrap(true)
        .can_unwrap(true)
        .can_decrypt(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC key bits must match each HMAC kind
#[session_test]
fn test_hmac_derived_key_prop_invalid_bits_all_kinds(session: HsmSession) {
    for (key_kind, bad_bits) in [
        (HsmKeyKind::HmacSha256, 128),
        (HsmKeyKind::HmacSha384, 256),
        (HsmKeyKind::HmacSha512, 384),
    ] {
        let hkdf_hash = hkdf_hash_for_hmac_key_kind(key_kind);
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let base_secret = derive_base_secret_for_hkdf(&session, curve);

        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(key_kind)
            .bits(bad_bits)
            .can_sign(true)
            .can_verify(true)
            .build()
            .unwrap();

        let result = derive_hmac_key_with_props(&session, &base_secret, hkdf_hash, props);

        assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
    }
}

/// HMAC must reject decrypt flag explicitly
#[session_test]
fn test_hmac_derived_key_prop_decrypt_flag_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_decrypt(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}
/// HMAC must reject when multiple invalid properties are combined
#[session_test]
fn test_hmac_derived_key_prop_multiple_invalid_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public) // invalid
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(128) // invalid
        .can_encrypt(true) // invalid
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(result.is_err());
}

#[session_test]
fn test_hmac_derived_key_prop_hash_mismatch_allowed(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha512)
        .bits(512)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    // Implementation allows mismatch
    assert!(result.is_ok());
}

#[session_test]
fn test_hmac_derived_key_prop_no_usage_flags_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(result.is_err());
}

/// Minimal valid HMAC props (only sign + verify) should succeed
#[session_test]
fn test_hmac_derived_key_prop_minimal_valid(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(result.is_ok());
}

/// Explicitly false flags should not break valid HMAC props
#[session_test]
fn test_hmac_derived_key_prop_explicit_false_flags_allowed(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_encrypt(false)
        .can_decrypt(false)
        .can_wrap(false)
        .can_unwrap(false)
        .can_derive(false)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(result.is_ok());
}

/// HMAC must reject overly large key sizes
#[session_test]
fn test_hmac_derived_key_prop_oversized_bits_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(1024) // too large
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC must reject mismatched key_kind and bit size
#[session_test]
fn test_hmac_derived_key_prop_kind_bits_cross_mismatch(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(512) // mismatch (should be 256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC must reject Private key class
#[session_test]
fn test_hmac_derived_key_prop_private_class_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HKDF must fail when using valid base secret but invalid props
#[session_test]
fn test_hmac_derive_rejects_invalid_props_even_with_valid_base(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    // invalid: missing sign
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_verify(true)
        .build()
        .unwrap();

    let mut hkdf_algo = HsmHkdfAlgo::new(HsmHashAlgo::Sha256, None, None).unwrap();

    let result = HsmKeyManager::derive_key(&session, &mut hkdf_algo, &base_secret, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC derived key should be non-session when is_session is false
#[session_test]
fn test_hmac_derived_key_prop_non_session_allowed(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .is_session(false)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let derived = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props)
        .expect("Expected success");

    assert!(!derived.is_session());
}

/// HMAC must reject wrap flag individually
#[session_test]
fn test_hmac_derived_key_prop_wrap_flag_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_wrap(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// HMAC should allow HKDF hash mismatch across all kinds
#[session_test]
fn test_hmac_hash_mismatch_all_kinds_allowed(session: HsmSession) {
    for key_kind in [
        HsmKeyKind::HmacSha256,
        HsmKeyKind::HmacSha384,
        HsmKeyKind::HmacSha512,
    ] {
        let curve = ecc_curve_for_hmac_key_kind(key_kind);
        let base_secret = derive_base_secret_for_hkdf(&session, curve);

        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(key_kind)
            .bits(match key_kind {
                HsmKeyKind::HmacSha256 => 256,
                HsmKeyKind::HmacSha384 => 384,
                HsmKeyKind::HmacSha512 => 512,
                _ => unreachable!(),
            })
            .can_sign(true)
            .can_verify(true)
            .build()
            .unwrap();

        let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

        assert!(result.is_ok());
    }
}

/// HMAC must reject unwrap flag individually
#[session_test]
fn test_hmac_derived_key_prop_unwrap_flag_rejected(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_unwrap(true)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let result = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

/// Derived HMAC key should preserve expected properties
#[session_test]
fn test_hmac_derived_key_properties_correct(session: HsmSession) {
    let base_secret = derive_base_secret_for_hkdf(&session, HsmEccCurve::P256);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::HmacSha256)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .build()
        .unwrap();

    let derived = derive_hmac_key_with_props(&session, &base_secret, HsmHashAlgo::Sha256, props)
        .expect("Expected success");

    assert_eq!(derived.bits(), 256);
    assert!(derived.can_sign());
    assert!(derived.can_verify());
}
