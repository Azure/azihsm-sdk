// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto as crypto;

// Helper functions

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

fn test_ecc_key_pair_generation_for_curve(session: &HsmSession, curve: HsmEccCurve) {
    // Create key properties for the private key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .build()
        .expect("Failed to build key props");

    // Create key properties for the public key
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .build()
        .expect("Failed to build key props");

    // Create the ECC key generation algorithm
    let mut algo = HsmEccKeyGenAlgo::default();

    // Generate the key pair
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        HsmKeyKind::Ecc,
        "Private key kind mismatch"
    );
    assert_eq!(
        priv_key.ecc_curve(),
        Some(curve),
        "Private key curve mismatch"
    );
    assert!(
        priv_key.is_local(),
        "Generated ECC private key should be local"
    );
    assert!(
        !priv_key.is_session(),
        "Private key should not be a session key"
    );
    assert!(
        priv_key.is_sensitive(),
        "Generated ECC private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Generated ECC keys should be extractable"
    );
    assert!(priv_key.can_sign(), "Private key should support signing");
    assert!(
        !priv_key.can_verify(),
        "Private key should not support verification"
    );
    assert!(
        !priv_key.can_encrypt(),
        "Private key should not support encryption"
    );
    assert!(
        !priv_key.can_decrypt(),
        "Private key should not support decryption"
    );
    assert!(
        !priv_key.can_wrap(),
        "Private key should not support wrapping"
    );
    assert!(
        !priv_key.can_unwrap(),
        "Private key should not support unwrapping"
    );
    assert!(
        !priv_key.can_derive(),
        "Private key should not support derivation"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Ecc, "Public key kind mismatch");
    assert_eq!(
        pub_key.ecc_curve(),
        Some(curve),
        "Public key curve mismatch"
    );
    assert!(
        pub_key.is_local(),
        "Generated ECC public key should be marked as local"
    );
    assert!(
        !pub_key.is_session(),
        "Public key should not be a session key"
    );
    assert!(
        !pub_key.is_sensitive(),
        "Generated ECC public key should not be marked as sensitive"
    );
    assert!(pub_key.is_extractable(), "Keys are always extractable");
    assert!(!pub_key.can_sign(), "Public key should not support signing");
    assert!(
        pub_key.can_verify(),
        "Public key should support verification"
    );
    assert!(
        !pub_key.can_encrypt(),
        "Public key should not support encryption"
    );
    assert!(
        !pub_key.can_decrypt(),
        "Public key should not support decryption"
    );
    assert!(
        !pub_key.can_wrap(),
        "Public key should not support wrapping"
    );
    assert!(
        !pub_key.can_unwrap(),
        "Public key should not support unwrapping"
    );
    assert!(
        !pub_key.can_derive(),
        "Public key should not support derivation"
    );

    drop(pub_key);

    // Get the public key
    let pub_key = priv_key.public_key();

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

fn test_unwrap_ecc_key_for_curve(
    session: HsmSession,
    crypto_curve: crypto::EccCurve,
    hsm_curve: HsmEccCurve,
    hash_algo: HsmHashAlgo,
) {
    use crypto::*;

    let priv_key =
        crypto::EccPrivateKey::from_curve(crypto_curve).expect("Failed to create ECC private key");
    let der = priv_key.to_vec().expect("Failed to export ECC Key");

    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash_algo, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap ECC Key");

    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(hsm_curve)
        .can_sign(true)
        .build()
        .expect("Failed to build private key props");
    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(hsm_curve)
        .can_verify(true)
        .build()
        .expect("Failed to build public key props");

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash_algo);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap ECC Key");

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        HsmKeyKind::Ecc,
        "Private key kind mismatch"
    );
    assert_eq!(
        priv_key.ecc_curve(),
        Some(hsm_curve),
        "Private key curve mismatch"
    );
    assert!(
        !priv_key.is_local(),
        "Unwrapped private key should not be local"
    );
    assert!(
        !priv_key.is_session(),
        "Unwrapped private key should not be a session key"
    );
    assert!(
        priv_key.is_sensitive(),
        "Unwrapped ECC private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Unwrapped ECC keys should be extractable"
    );
    assert!(priv_key.can_sign(), "Private key should support signing");
    assert!(
        !priv_key.can_verify(),
        "Private key should not support verification"
    );
    assert!(
        !priv_key.can_encrypt(),
        "Private key should not support encryption"
    );
    assert!(
        !priv_key.can_decrypt(),
        "Private key should not support decryption"
    );
    assert!(
        !priv_key.can_wrap(),
        "Private key should not support wrapping"
    );
    assert!(
        !priv_key.can_unwrap(),
        "Private key should not support unwrapping"
    );
    assert!(
        !priv_key.can_derive(),
        "Private key should not support derivation"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Ecc, "Public key kind mismatch");
    assert_eq!(
        pub_key.ecc_curve(),
        Some(hsm_curve),
        "Public key curve mismatch"
    );
    assert!(
        !pub_key.is_local(),
        "Unwrapped public key should not be local"
    );
    assert!(
        !pub_key.is_session(),
        "Unwrapped public key should not be a session key"
    );
    assert!(
        !pub_key.is_sensitive(),
        "Public key should not be sensitive"
    );
    assert!(pub_key.is_extractable(), "Keys are always extractable");
    assert!(!pub_key.can_sign(), "Public key should not support signing");
    assert!(
        pub_key.can_verify(),
        "Public key should support verification"
    );
    assert!(
        !pub_key.can_encrypt(),
        "Public key should not support encryption"
    );
    assert!(
        !pub_key.can_decrypt(),
        "Public key should not support decryption"
    );
    assert!(
        !pub_key.can_wrap(),
        "Public key should not support wrapping"
    );
    assert!(
        !pub_key.can_unwrap(),
        "Public key should not support unwrapping"
    );
    assert!(
        !pub_key.can_derive(),
        "Public key should not support derivation"
    );

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

fn compare_ecc_private_key_properties(original: &HsmEccPrivateKey, unmasked: &HsmEccPrivateKey) {
    assert_eq!(
        original.class(),
        unmasked.class(),
        "Private key class mismatch"
    );
    assert_eq!(
        original.kind(),
        unmasked.kind(),
        "Private key kind mismatch"
    );
    assert_eq!(
        original.ecc_curve(),
        unmasked.ecc_curve(),
        "Private key curve mismatch"
    );
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Private key sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Private key verify capability mismatch"
    );
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Private key encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Private key decrypt capability mismatch"
    );
    assert_eq!(
        original.can_wrap(),
        unmasked.can_wrap(),
        "Private key wrap capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Private key unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Private key derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Private key session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Private key local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Private key sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Private key extractable flag mismatch"
    );
}

fn compare_ecc_public_key_properties(original: &HsmEccPublicKey, unmasked: &HsmEccPublicKey) {
    assert_eq!(
        original.class(),
        unmasked.class(),
        "Public key class mismatch"
    );
    assert_eq!(original.kind(), unmasked.kind(), "Public key kind mismatch");
    assert_eq!(
        original.ecc_curve(),
        unmasked.ecc_curve(),
        "Public key curve mismatch"
    );
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Public key sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Public key verify capability mismatch"
    );
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Public key encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Public key decrypt capability mismatch"
    );
    assert_eq!(
        original.can_wrap(),
        unmasked.can_wrap(),
        "Public key wrap capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Public key unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Public key derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Public key session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Public key local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Public key sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Public key extractable flag mismatch"
    );
}

/// Helper function to test ECC key pair unmasking for a specific curve.
fn test_ecc_key_unmask_for_curve(session: &HsmSession, curve: HsmEccCurve) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut gen_algo = HsmEccKeyGenAlgo::default();
    let (original_priv_key, original_pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut gen_algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    // Get the masked key from the private key (this includes both keys in the pair)
    let masked_key_pair = original_priv_key
        .masked_key_vec()
        .expect("Failed to get masked private key");

    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();
    let (unmasked_priv_key, unmasked_pub_key) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked_key_pair)
            .expect("Failed to unmask ECC key pair");

    compare_ecc_private_key_properties(&original_priv_key, &unmasked_priv_key);
    compare_ecc_public_key_properties(&original_pub_key, &unmasked_pub_key);

    HsmKeyManager::delete_key(original_priv_key).expect("Failed to delete original private key");
    HsmKeyManager::delete_key(original_pub_key).expect("Failed to delete original public key");
    HsmKeyManager::delete_key(unmasked_priv_key).expect("Failed to delete unmasked private key");
    HsmKeyManager::delete_key(unmasked_pub_key).expect("Failed to delete unmasked public key");
}

// Tests

/// Test ECC key pair generation.
///
/// Verifies that an ECC P-256 key pair can be successfully generated within
/// an HSM session with sign and verify capabilities.
#[session_test]
fn test_ecc_p256_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P256);
}

#[session_test]
fn test_ecc_p384_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P384);
}

#[session_test]
fn test_ecc_p521_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P521);
}

#[session_test]
fn test_unwrap_ecc_p256_key(session: HsmSession) {
    test_unwrap_ecc_key_for_curve(
        session,
        crypto::EccCurve::P256,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha1,
    );
}

#[session_test]
fn test_unwrap_ecc_p384_key(session: HsmSession) {
    test_unwrap_ecc_key_for_curve(
        session,
        crypto::EccCurve::P384,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

//implement p521 unwrap test
#[session_test]
fn test_unwrap_ecc_p521_key(session: HsmSession) {
    test_unwrap_ecc_key_for_curve(
        session,
        crypto::EccCurve::P521,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
    );
}

/// Test ECC P256 key pair unmasking.
///
/// Generates an ECC P256 key pair, retrieves the masked key data,
/// unmasks it, and verifies all properties match the original keys.
#[session_test]
fn test_ecc_p256_key_unmask(session: HsmSession) {
    test_ecc_key_unmask_for_curve(&session, HsmEccCurve::P256);
}

/// Test ECC P384 key pair unmasking.
#[session_test]
fn test_ecc_p384_key_unmask(session: HsmSession) {
    test_ecc_key_unmask_for_curve(&session, HsmEccCurve::P384);
}

/// Test ECC P521 key pair unmasking.
#[session_test]
fn test_ecc_p521_key_unmask(session: HsmSession) {
    test_ecc_key_unmask_for_curve(&session, HsmEccCurve::P521);
}

/// Test generating a key report for an ECC P-256 key.
///
/// Verifies that a key report can be successfully generated for an ECC private key,
/// including custom report data and proper size calculation.
#[session_test]
fn test_ecc_p256_key_report(session: HsmSession) {
    // Generate an ECC P-256 key pair
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    let mut algo = HsmEccKeyGenAlgo::default();
    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    // Custom report data (128 bytes is the max)
    let report_data = [0x42u8; 128];

    // First call: get the required buffer size
    let report_size = HsmKeyManager::generate_key_report(&priv_key, &report_data, None)
        .expect("Failed to get key report size");

    assert!(report_size > 0, "Report size should be greater than 0");

    // Second call: generate the actual report
    let mut report_buffer = vec![0u8; report_size];
    let actual_size =
        HsmKeyManager::generate_key_report(&priv_key, &report_data, Some(&mut report_buffer))
            .expect("Failed to generate key report");
    report_buffer.truncate(actual_size);

    // Verify the report buffer was populated (not all zeros)
    let non_zero_bytes = report_buffer.iter().filter(|&&b| b != 0).count();
    assert!(non_zero_bytes > 0, "Report should contain non-zero data");

    // Clean up: delete the keys
    HsmKeyManager::delete_key(priv_key).expect("Failed to delete ECC private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete ECC public key");
}

/// Test ECC key pair unmasking with derive capability.
///
/// Generates an ECC P-256 key pair with derive enabled, retrieves the masked key data,
/// unmasks it, and verifies all properties match the original keys.
#[session_test]
fn test_ecc_p256_key_unmask_with_derive(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_derive(true)
        .build()
        .expect("Failed to build public key props");

    let mut gen_algo = HsmEccKeyGenAlgo::default();
    let (original_priv_key, original_pub_key) =
        HsmKeyManager::generate_key_pair(&session, &mut gen_algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    let masked_key_pair = original_priv_key
        .masked_key_vec()
        .expect("Failed to get masked private key");

    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();
    let (unmasked_priv_key, unmasked_pub_key) =
        HsmKeyManager::unmask_key_pair(&session, &mut unmask_algo, &masked_key_pair)
            .expect("Failed to unmask ECC key pair");

    compare_ecc_private_key_properties(&original_priv_key, &unmasked_priv_key);
    compare_ecc_public_key_properties(&original_pub_key, &unmasked_pub_key);
}
