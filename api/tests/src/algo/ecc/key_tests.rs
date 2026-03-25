// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto as crypto;

// ================================
// Helper functions
// ================================

/// Generates an RSA key pair for unwrapping operations.
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

/// Generates an ECC key pair for the specified curve and verifies all key attributes.
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

/// Unwraps an ECC key for the specified curve using RSA-AES wrapping and verifies
/// all resulting key properties.
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

/// Compares all attributes of two ECC private keys and asserts they are identical.
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

/// Compares all attributes of two ECC public keys and asserts they are identical.
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

/// Generates, masks, and unmasks an ECC key pair and verifies all properties are preserved.
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

/// Builds ECC private key properties with configurable SIGN and DERIVE capabilities.
pub(crate) fn ecc_priv_props(curve: HsmEccCurve, can_sign: bool, can_derive: bool) -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_sign(can_sign)
        .can_derive(can_derive)
        .build()
        .unwrap()
}

/// Builds ECC public key properties with configurable VERIFY and DERIVE capabilities.
pub(crate) fn ecc_pub_props(curve: HsmEccCurve, can_verify: bool, can_derive: bool) -> HsmKeyProps {
    HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(curve)
        .can_verify(can_verify)
        .can_derive(can_derive)
        .build()
        .unwrap()
}

/// Attempts to unwrap an ECC key pair using the provided properties and ciphertext.
fn unwrap_ecc(
    session: &HsmSession,
    hash: HsmHashAlgo,
    priv_props: HsmKeyProps,
    pub_props: HsmKeyProps,
    ciphertext: &[u8],
) -> Result<(HsmEccPrivateKey, HsmEccPublicKey), HsmError> {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash);

    HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        ciphertext,
        priv_props,
        pub_props,
    )
}

/// Executes an unwrap operation and asserts that it fails.
fn expect_unwrap_err(
    session: &HsmSession,
    hash: HsmHashAlgo,
    priv_props: HsmKeyProps,
    pub_props: HsmKeyProps,
    ciphertext: &[u8],
) {
    let result = unwrap_ecc(session, hash, priv_props, pub_props, ciphertext);
    assert!(result.is_err());
}

/// Verifies unwrap succeeds when both private and public keys use DERIVE capability.
fn expect_unwrap_ok_with_derive(
    session: &HsmSession,
    crypto_curve: crypto::EccCurve,
    hsm_curve: HsmEccCurve,
    hash: HsmHashAlgo,
) {
    use crypto::*;

    let priv_key = EccPrivateKey::from_curve(crypto_curve).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (rsa_priv, rsa_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &rsa_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(hsm_curve)
        .can_derive(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(hsm_curve)
        .can_derive(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_ok());
}

/// Generates a key report for an ECC private key and verifies size and content.
fn run_ecc_key_report_test(session: &HsmSession, curve: HsmEccCurve) {
    // Build key props
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

    let mut algo = HsmEccKeyGenAlgo::default();

    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    let report_data = [0x42u8; 128];

    // First call → size
    let report_size = HsmKeyManager::generate_key_report(&priv_key, &report_data, None)
        .expect("Failed to get key report size");

    assert!(report_size > 0, "Report size should be > 0");

    // Second call → actual report
    let mut buffer = vec![0u8; report_size];

    let actual_size =
        HsmKeyManager::generate_key_report(&priv_key, &report_data, Some(&mut buffer))
            .expect("Failed to generate key report");

    buffer.truncate(actual_size);

    assert!(
        buffer.iter().any(|&b| b != 0),
        "Report should contain non-zero data"
    );

    // cleanup
    HsmKeyManager::delete_key(priv_key).expect("Failed to delete private key after report test");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete public key after report test");
}

/// Generates, masks, and unmasks an ECC key pair with DERIVE capability and verifies
/// that all properties are preserved.
fn run_ecc_key_unmask_with_derive_test(session: &HsmSession, curve: HsmEccCurve) {
    // Build props (derive enabled, no sign)
    let priv_key_props = ecc_priv_props(curve, false, true);
    let pub_key_props = ecc_pub_props(curve, false, true);

    let mut gen_algo = HsmEccKeyGenAlgo::default();

    let (original_priv_key, original_pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut gen_algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    // Mask
    let masked = original_priv_key
        .masked_key_vec()
        .expect("Failed to get masked private key");

    // Unmask
    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();

    let (unmasked_priv, unmasked_pub) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked)
            .expect("Failed to unmask ECC key pair");

    // Compare
    compare_ecc_private_key_properties(&original_priv_key, &unmasked_priv);
    compare_ecc_public_key_properties(&original_pub_key, &unmasked_pub);

    // Cleanup (use expect for consistency)
    HsmKeyManager::delete_key(original_priv_key).expect("Failed to delete original private key");
    HsmKeyManager::delete_key(original_pub_key).expect("Failed to delete original public key");
    HsmKeyManager::delete_key(unmasked_priv).expect("Failed to delete unmasked private key");
    HsmKeyManager::delete_key(unmasked_pub).expect("Failed to delete unmasked public key");
}

/// Verifies unwrap fails when the public key is configured with both VERIFY and DERIVE.
fn run_ecc_unwrap_reject_public_verify_and_derive(
    session: &HsmSession,
    curve: HsmEccCurve,
    hash: HsmHashAlgo,
) {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash);

    // Use helpers for consistency
    let priv_props = ecc_priv_props(curve, true, false); // can_sign = true
    let pub_props = ecc_pub_props(curve, true, true); // can_verify + can_derive (invalid combo)

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        &[0u8; 32], // dummy ciphertext
        priv_props,
        pub_props,
    );

    assert!(
        result.is_err(),
        "Expected unwrap to fail for invalid public flags"
    );
}

/// Verifies ECC key unmasking succeeds for SIGN-capable private keys and preserves key properties.
fn run_ecc_key_unmask_with_sign_test(session: &HsmSession, curve: HsmEccCurve) {
    let priv_key_props = ecc_priv_props(curve, true, false); // SIGN only
    let pub_key_props = ecc_pub_props(curve, true, false);

    let mut gen_algo = HsmEccKeyGenAlgo::default();

    let (original_priv, original_pub) =
        HsmKeyManager::generate_key_pair(session, &mut gen_algo, priv_key_props, pub_key_props)
            .expect("Failed to generate ECC key pair");

    let masked = original_priv
        .masked_key_vec()
        .expect("Failed to get masked key");

    let mut unmask_algo = HsmEccKeyUnmaskAlgo::default();

    let (unmasked_priv, unmasked_pub) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked)
            .expect("Failed to unmask ECC key pair");

    compare_ecc_private_key_properties(&original_priv, &unmasked_priv);
    compare_ecc_public_key_properties(&original_pub, &unmasked_pub);

    HsmKeyManager::delete_key(original_priv).unwrap();
    HsmKeyManager::delete_key(original_pub).unwrap();
    HsmKeyManager::delete_key(unmasked_priv).unwrap();
    HsmKeyManager::delete_key(unmasked_pub).unwrap();
}

/// Verifies ECC key wrap and unwrap round-trip succeeds and produces keys with expected properties.
fn run_ecc_round_trip_test(
    session: &HsmSession,
    crypto_curve: crypto::EccCurve,
    hsm_curve: HsmEccCurve,
    hash: HsmHashAlgo,
) {
    use crypto::*;

    let original = EccPrivateKey::from_curve(crypto_curve).unwrap();
    let der = original.to_vec().unwrap();

    let (rsa_priv, rsa_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(hash, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &rsa_pub, &der).unwrap();

    let priv_props = ecc_priv_props(hsm_curve, true, false);
    let pub_props = ecc_pub_props(hsm_curve, true, false);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(hash);

    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("Failed round-trip unwrap");

    // sanity check: key exists + correct curve
    assert_eq!(priv_key.ecc_curve(), Some(hsm_curve));
    assert_eq!(pub_key.ecc_curve(), Some(hsm_curve));

    HsmKeyManager::delete_key(priv_key).unwrap();
    HsmKeyManager::delete_key(pub_key).unwrap();
}

/// Verifies ECC unwrap fails when private and public key curves do not match,
/// and that validation occurs before reaching the DDI layer.
fn run_ecc_unwrap_reject_curve_mismatch_test(
    session: &HsmSession,
    priv_curve: HsmEccCurve,
    pub_curve: HsmEccCurve,
) {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let priv_props = ecc_priv_props(priv_curve, true, false);
    let pub_props = ecc_pub_props(pub_curve, true, false);

    // bogus wrapped blob → ensures validation happens before DDI
    let result =
        HsmKeyManager::unwrap_key_pair(&mut unwrap_algo, &rsa_priv, &[], priv_props, pub_props);

    assert!(matches!(result, Err(HsmError::InvalidKeyProps)));
}

// ============================================================
// test cases sections
// ============================================================

/// Test ECC key pair generation.
///
/// Verifies that an ECC P-256 key pair can be successfully generated within
/// an HSM session with sign and verify capabilities.
#[session_test]
fn test_ecc_p256_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P256);
}

/// Verifies ECC P-384 key pair generation with correct properties and capabilities.
#[session_test]
fn test_ecc_p384_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P384);
}

/// Verifies ECC P-521 key pair generation with correct properties and capabilities.
#[session_test]
fn test_ecc_p521_key_pair_generation(session: HsmSession) {
    test_ecc_key_pair_generation_for_curve(&session, HsmEccCurve::P521);
}

/// Verifies successful unwrap of an ECC P-256 key using RSA-AES wrapping.
#[session_test]
fn test_unwrap_ecc_p256_key(session: HsmSession) {
    test_unwrap_ecc_key_for_curve(
        session,
        crypto::EccCurve::P256,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha1,
    );
}

/// Verifies successful unwrap of an ECC P-384 key using RSA-AES wrapping.
#[session_test]
fn test_unwrap_ecc_p384_key(session: HsmSession) {
    test_unwrap_ecc_key_for_curve(
        session,
        crypto::EccCurve::P384,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies successful unwrap of an ECC P-521 key using RSA-AES wrapping.
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
    run_ecc_key_report_test(&session, HsmEccCurve::P256);
}

/// Verifies key report generation for ECC P-384 key including size and content validation.

#[session_test]
fn test_ecc_p384_key_report(session: HsmSession) {
    run_ecc_key_report_test(&session, HsmEccCurve::P384);
}

/// Verifies key report generation for ECC P-521 key including size and content validation.
#[session_test]
fn test_ecc_p521_key_report(session: HsmSession) {
    run_ecc_key_report_test(&session, HsmEccCurve::P521);
}

/// Test ECC key pair unmasking with derive capability.
///
/// Generates an ECC P-256 key pair with derive enabled, retrieves the masked key data,
/// unmasks it, and verifies all properties match the original keys.
#[session_test]
fn test_ecc_p256_key_unmask_with_derive(session: HsmSession) {
    run_ecc_key_unmask_with_derive_test(&session, HsmEccCurve::P256);
}

/// Verifies ECC P-384 key unmasking with derive capability preserves all properties.
#[session_test]
fn test_ecc_p384_key_unmask_with_derive(session: HsmSession) {
    run_ecc_key_unmask_with_derive_test(&session, HsmEccCurve::P384);
}

/// Verifies ECC P-521 key unmasking with derive capability preserves all properties.
#[session_test]
fn test_ecc_p521_key_unmask_with_derive(session: HsmSession) {
    run_ecc_key_unmask_with_derive_test(&session, HsmEccCurve::P521);
}

/// Verifies ECC key P256 generation fails when public key requests VERIFY
/// but private key does not have SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_private_verify_without_sign_p256(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, false, true);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props);

    assert!(
        result.is_err(),
        "Expected failure for invalid private flags"
    );
}

/// Verifies ECC key P384 generation fails when public key requests VERIFY
/// but private key does not have SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_private_verify_without_sign_p384(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P384, false, true);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ECC key P521 generation fails when public key requests VERIFY
/// but private key does not have SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_private_verify_without_sign_p521(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P521, false, true);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ecc key p256 generation fails when public key incorrectly has SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_public_sign_flag_p256(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props);

    assert!(result.is_err(), "Expected failure for invalid public flags");
}

/// Verifies ecc key p384 generation fails when public key incorrectly has SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_public_sign_flag_p384(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P384, true, false);

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .build()
        .unwrap();

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ecc key p521 generation fails when public key incorrectly has SIGN capability.
#[session_test]
fn test_ecc_keygen_reject_public_sign_flag_p521(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P521, true, false);

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P521)
        .can_sign(true)
        .build()
        .unwrap();

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies  ecc key P256 generation fails when private and public curves do not match.
#[session_test]
fn test_ecc_keygen_reject_curve_mismatch_p256(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_key_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props);

    assert!(result.is_err(), "Expected failure for curve mismatch");
}

/// Verifies  ecc key P384 generation fails when private and public curves do not match.
#[session_test]
fn test_ecc_keygen_reject_curve_mismatch_p384(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P384, true, false);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies  ecc key P521 generation fails when private and public curves do not match.
#[session_test]
fn test_ecc_keygen_reject_curve_mismatch_p521(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P521, true, false);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies key generation fails when public VERIFY is set but private cannot SIGN.
#[session_test]
fn test_ecc_keygen_reject_verify_without_private_sign(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, false, true);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    let result =
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props);

    assert!(result.is_err(), "Expected failure when VERIFY without SIGN");
}

/// Verifies ECC P521 key generation fails when private key sets both SIGN and DERIVE simultaneously.
#[session_test]
fn test_ecc_keygen_reject_private_sign_and_derive_p521(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P521, true, true);
    let pub_key_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies key generation fails when public key sets both VERIFY and DERIVE simultaneously.
#[session_test]
fn test_ecc_keygen_reject_public_verify_and_derive(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, true);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ECC P256 key generation fails when private key has no usage flags set.
#[session_test]
fn test_ecc_keygen_reject_no_usage_flags_p256(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P256, false, false);

    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ECC P384 key generation fails when private key has no usage flags set.
#[session_test]
fn test_ecc_keygen_reject_no_usage_flags_p384(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P384, false, false);

    let pub_key_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies ECC P521 key generation fails when private key has no usage flags set.
#[session_test]
fn test_ecc_keygen_reject_no_usage_flags_p521(session: HsmSession) {
    let priv_key_props = ecc_priv_props(HsmEccCurve::P521, false, false);

    let pub_key_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies key generation fails when private key uses incorrect key kind (non-ECC).
#[session_test]
fn test_ecc_keygen_reject_wrong_key_kind(session: HsmSession) {
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();
    let pub_key_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut algo = HsmEccKeyGenAlgo::default();

    assert!(
        HsmKeyManager::generate_key_pair(&session, &mut algo, priv_key_props, pub_key_props)
            .is_err()
    );
}

/// Verifies unmask operation fails when provided corrupted masked key data.
#[session_test]
fn test_ecc_unmask_reject_corrupted_data(session: HsmSession) {
    let mut algo = HsmEccKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key_pair(&session, &mut algo, &[1, 2, 3, 4]);

    assert!(result.is_err(), "Expected failure for corrupted masked key");
}

/// Verifies ECC Key P256 unwrap operation fails when ciphertext is invalid or malformed.
#[session_test]
fn test_ecc_unwrap_reject_invalid_ciphertext_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 10],
    );
}

/// Verifies ECC Key P384 unwrap operation fails when ciphertext is invalid or malformed.
#[session_test]
fn test_ecc_unwrap_reject_invalid_ciphertext_p384(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P384, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha384,
        priv_props,
        pub_props,
        &[0u8; 10],
    );
}

/// Verifies ECC Key P521 unwrap operation fails when ciphertext is invalid or malformed.
#[session_test]
fn test_ecc_unwrap_reject_invalid_ciphertext_p521(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P521, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512,
        priv_props,
        pub_props,
        &[0u8; 10],
    );
}

/// Verifies unwrap operation fails when ECC curve in properties does not match wrapped key.
#[session_test]
fn test_ecc_unwrap_reject_curve_mismatch(session: HsmSession) {
    use crypto::*;

    let priv_key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P384)
        .can_verify(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err());
}

/// Verifies ECC P256 unwrap succeeds when using DERIVE capability instead of SIGN.

#[session_test]
fn test_unwrap_ecc_p256_key_with_derive(session: HsmSession) {
    expect_unwrap_ok_with_derive(
        &session,
        crypto::EccCurve::P256,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies ECC P384 unwrap succeeds when using DERIVE capability instead of SIGN.
#[session_test]
fn test_unwrap_ecc_p384_key_with_derive(session: HsmSession) {
    expect_unwrap_ok_with_derive(
        &session,
        crypto::EccCurve::P384,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies ECC p521 unwrap succeeds when using DERIVE capability instead of SIGN.
#[session_test]
fn test_unwrap_ecc_p521_key_with_derive(session: HsmSession) {
    expect_unwrap_ok_with_derive(
        &session,
        crypto::EccCurve::P521,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
    );
}

/// Verifies unwrap ECC Key p256 fails when private key has both SIGN and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_private_sign_and_derive_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies unwrap ECC Key p384 fails when private key has both SIGN and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_private_sign_and_derive_p384(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P384, true, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies unwrap ECC Key p521 fails when private key has both SIGN and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_private_sign_and_derive_p521(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P521, true, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies ECC key p256 unwrap fails when public key has both VERIFY and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_public_verify_and_derive_p256(session: HsmSession) {
    run_ecc_unwrap_reject_public_verify_and_derive(
        &session,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies ECC key p384 unwrap fails when public key has both VERIFY and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_public_verify_and_derive_p384(session: HsmSession) {
    run_ecc_unwrap_reject_public_verify_and_derive(
        &session,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

/// Verifies ECC key p521 unwrap fails when public key has both VERIFY and DERIVE.
#[session_test]
fn test_ecc_unwrap_reject_public_verify_and_derive_p521(session: HsmSession) {
    run_ecc_unwrap_reject_public_verify_and_derive(
        &session,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
    );
}

/// Verifies ECC key p256 unwrap fails when ciphertext is empty.
#[session_test]
fn test_ecc_unwrap_reject_empty_ciphertext_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(&session, HsmHashAlgo::Sha256, priv_props, pub_props, &[]);
}

/// Verifies ECC key p384 unwrap fails when ciphertext is empty.
#[session_test]
fn test_ecc_unwrap_reject_empty_ciphertext_p384(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P384, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(&session, HsmHashAlgo::Sha256, priv_props, pub_props, &[]);
}
/// Verifies ECC key p521 unwrap fails when ciphertext is empty.
#[session_test]
fn test_ecc_unwrap_reject_empty_ciphertext_p521(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P521, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(&session, HsmHashAlgo::Sha512, priv_props, pub_props, &[]);
}

/// Verifies ECC Key p256 unwrap fails when ciphertext is too small.
#[session_test]
fn test_ecc_unwrap_reject_small_ciphertext_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[1, 2],
    );
}

/// Verifies ECC Key p384 unwrap fails when ciphertext is too small.
#[session_test]
fn test_ecc_unwrap_reject_small_ciphertext_p384(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P384, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[1, 2],
    );
}

/// Verifies ECC Key p521 unwrap fails when ciphertext is too small.
#[session_test]
fn test_ecc_unwrap_reject_small_ciphertext_p521(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P521, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512,
        priv_props,
        pub_props,
        &[1, 2],
    );
}

/// Verifies ECC key p256 unwrap fails when private allows DERIVE but public requires VERIFY.
#[session_test]
fn test_ecc_unwrap_reject_derive_mismatch_p256(session: HsmSession) {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(&session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let priv_props = ecc_priv_props(HsmEccCurve::P256, false, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        &[0u8; 32],
        priv_props,
        pub_props,
    );

    assert!(result.is_err());
}

/// Verifies ECC key p384 unwrap fails when private allows DERIVE but public requires VERIFY.
#[session_test]
fn test_ecc_unwrap_reject_derive_mismatch_p384(session: HsmSession) {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(&session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let priv_props = ecc_priv_props(HsmEccCurve::P384, false, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);
    assert!(
        HsmKeyManager::unwrap_key_pair(
            &mut unwrap_algo,
            &rsa_priv,
            &[0u8; 32],
            priv_props,
            pub_props,
        )
        .is_err()
    );
}

/// Verifies ECC key p521 unwrap fails when private allows DERIVE but public requires VERIFY.
#[session_test]
fn test_ecc_unwrap_reject_derive_mismatch_p521(session: HsmSession) {
    let (rsa_priv, _) = get_rsa_unwrapping_key_pair(&session);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha512);

    let priv_props = ecc_priv_props(HsmEccCurve::P521, false, true);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);
    assert!(
        HsmKeyManager::unwrap_key_pair(
            &mut unwrap_algo,
            &rsa_priv,
            &[0u8; 32],
            priv_props,
            pub_props,
        )
        .is_err()
    );
}

#[session_test]
fn test_ecc_unwrap_reject_tampered_ciphertext(session: HsmSession) {
    use crypto::*;

    let priv_key = EccPrivateKey::from_curve(EccCurve::P256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (rsa_priv, rsa_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &rsa_pub, &der).unwrap();

    // Tamper → guaranteed failure
    wrapped[5] ^= 0xAA;

    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    let mut unwrap_algo = HsmEccKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &rsa_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err());
}

/// Verifies ECC key P256 unwrap fails when private key uses incorrect key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_reject_wrong_key_kind_p256(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa) // wrong
        .ecc_curve(HsmEccCurve::P256)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC key P384 unwrap fails when private key uses incorrect key kind (non-ECC).
fn test_ecc_unwrap_reject_wrong_key_kind_p384(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa) // invalid
        .ecc_curve(HsmEccCurve::P384)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC key P521 unwrap fails when private key uses incorrect key kind (non-ECC).
fn test_ecc_unwrap_reject_wrong_key_kind_p521(session: HsmSession) {
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa) // invalid
        .ecc_curve(HsmEccCurve::P521)
        .can_sign(true)
        .build()
        .unwrap();

    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC key P256 unwrap fails when private key has no usage flags set.
fn test_ecc_unwrap_reject_no_usage_flags_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, false, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC key P384 unwrap fails when private key has no usage flags set.
fn test_ecc_unwrap_reject_no_usage_flags_p384(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P384, false, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P384, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC key P521 unwrap fails when private key has no usage flags set.
fn test_ecc_unwrap_reject_no_usage_flags_p521(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P521, false, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P521, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

#[session_test]
/// Verifies ECC P256 key unmasking with SIGN capability preserves all properties.
fn test_ecc_p256_key_unmask_with_sign(session: HsmSession) {
    run_ecc_key_unmask_with_sign_test(&session, HsmEccCurve::P256);
}

#[session_test]
/// Verifies ECC P384 key unmasking with SIGN capability preserves all properties.
fn test_ecc_p384_key_unmask_with_sign(session: HsmSession) {
    run_ecc_key_unmask_with_sign_test(&session, HsmEccCurve::P384);
}

#[session_test]
/// Verifies ECC P521 key unmasking with SIGN capability preserves all properties.
fn test_ecc_p521_key_unmask_with_sign(session: HsmSession) {
    run_ecc_key_unmask_with_sign_test(&session, HsmEccCurve::P521);
}

#[session_test]
/// Verifies ECC P256 round-trip (wrap → unwrap) succeeds.
fn test_ecc_p256_round_trip(session: HsmSession) {
    run_ecc_round_trip_test(
        &session,
        crypto::EccCurve::P256,
        HsmEccCurve::P256,
        HsmHashAlgo::Sha256,
    );
}

#[session_test]
/// Verifies ECC P384 round-trip (wrap → unwrap) succeeds.
fn test_ecc_p384_round_trip(session: HsmSession) {
    run_ecc_round_trip_test(
        &session,
        crypto::EccCurve::P384,
        HsmEccCurve::P384,
        HsmHashAlgo::Sha256,
    );
}

#[session_test]
/// Verifies ECC P521 round-trip (wrap → unwrap) succeeds.
fn test_ecc_p521_round_trip(session: HsmSession) {
    run_ecc_round_trip_test(
        &session,
        crypto::EccCurve::P521,
        HsmEccCurve::P521,
        HsmHashAlgo::Sha512,
    );
}

#[session_test]
/// Verifies ECC unwrap fails when private and public curves do not match (P256 vs P384).
fn test_ecc_unwrap_reject_curve_mismatch_p256_p384(session: HsmSession) {
    run_ecc_unwrap_reject_curve_mismatch_test(&session, HsmEccCurve::P256, HsmEccCurve::P384);
}

#[session_test]
/// Verifies ECC unwrap fails when private and public curves do not match (P384 vs P521).
fn test_ecc_unwrap_reject_curve_mismatch_p384_p521(session: HsmSession) {
    run_ecc_unwrap_reject_curve_mismatch_test(&session, HsmEccCurve::P384, HsmEccCurve::P521);
}

#[session_test]
/// Verifies ECC unwrap fails when private and public curves do not match (P521 vs P256).
fn test_ecc_unwrap_reject_curve_mismatch_p521_p256(session: HsmSession) {
    run_ecc_unwrap_reject_curve_mismatch_test(&session, HsmEccCurve::P521, HsmEccCurve::P256);
}

/// Verifies ECC unwrap fails when the public key properties use an invalid class (non-Public).
#[session_test]
fn test_ecc_unwrap_reject_public_wrong_class(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // invalid
        .key_kind(HsmKeyKind::Ecc)
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies ECC unwrap fails when the public key properties use an incorrect key kind (non-ECC).
#[session_test]
fn test_ecc_unwrap_reject_public_wrong_key_kind(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa) // invalid
        .ecc_curve(HsmEccCurve::P256)
        .can_verify(true)
        .build()
        .unwrap();

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies ECC unwrap fails when the public key has no usage flags set.
#[session_test]
fn test_ecc_unwrap_reject_public_no_usage_flags(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);

    let pub_props = ecc_pub_props(HsmEccCurve::P256, false, false); // invalid

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha256,
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}

/// Verifies ECC unwrap fails when using a hash algorithm incompatible with the curve.
#[session_test]
fn test_ecc_unwrap_hash_mismatch_p256(session: HsmSession) {
    let priv_props = ecc_priv_props(HsmEccCurve::P256, true, false);
    let pub_props = ecc_pub_props(HsmEccCurve::P256, true, false);

    expect_unwrap_err(
        &session,
        HsmHashAlgo::Sha512, // mismatch
        priv_props,
        pub_props,
        &[0u8; 32],
    );
}
