// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto as crypto;

use super::*;

// ================================
// Helper functions
// ================================

/// Helper to generate RSA unwrapping key pair with wrap/unwrap capabilities
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

/// Helper to unwrap RSA key and validate properties for a given key size
fn test_unwrap_rsa_key_for_bits(
    session: &HsmSession,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    use crypto::*;

    // Generate RSA key using azihsm_crypto
    let priv_key =
        crypto::RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    // Get unwrapping key pair
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    // Wrap the generated key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    // Define properties for the unwrapped key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap the key pair
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        HsmKeyKind::Rsa,
        "Private key kind mismatch"
    );
    assert_eq!(priv_key.bits(), bits, "Private key bits mismatch");
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
        "Unwrapped RSA private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Unwrapped RSA keys should be extractable"
    );
    assert!(
        priv_key.can_decrypt(),
        "Private key should support decryption"
    );
    assert!(
        !priv_key.can_sign(),
        "Private key should not support signing"
    );
    assert!(
        !priv_key.can_unwrap(),
        "Private key should not support unwrapping"
    );
    assert!(
        priv_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa, "Public key kind mismatch");
    assert_eq!(pub_key.bits(), bits, "Public key bits mismatch");
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
    assert!(
        pub_key.can_encrypt(),
        "Public key should support encryption"
    );
    assert!(
        !pub_key.can_verify(),
        "Public key should not support verification"
    );
    assert!(
        !pub_key.can_wrap(),
        "Public key should not support wrapping"
    );
    assert!(
        pub_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    HsmKeyManager::delete_key(priv_key).expect("Failed to delete RSA private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete RSA public key");
}

/// Helper to compare all private key properties between original and unmasked keys
fn compare_rsa_private_key_properties(original: &HsmRsaPrivateKey, unmasked: &HsmRsaPrivateKey) {
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
        original.bits(),
        unmasked.bits(),
        "Private key bits mismatch"
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

/// Helper to compare all public key properties between original and unmasked keys
fn compare_rsa_public_key_properties(original: &HsmRsaPublicKey, unmasked: &HsmRsaPublicKey) {
    assert_eq!(
        original.class(),
        unmasked.class(),
        "Public key class mismatch"
    );
    assert_eq!(original.kind(), unmasked.kind(), "Public key kind mismatch");
    assert_eq!(original.bits(), unmasked.bits(), "Public key bits mismatch");
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

/// Helper function to test RSA key pair unmasking.
/// Since the device only supports generating unwrapping keys for RSA, this test:
/// 1. Generates a crypto RSA key and unwraps it into the HSM
/// 2. Extracts the masked_key_vec from the unwrapped key
/// 3. Unmasks it using unmask_key_pair
/// 4. Verifies all properties match between the unwrapped and unmasked keys
fn test_rsa_key_unmask_for_bits(
    session: &HsmSession,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    use crypto::*;

    // Generate RSA key using azihsm_crypto
    let crypto_priv_key =
        crypto::RsaPrivateKey::generate(key_size_bytes).expect("Failed to generate RSA Key");
    let der = crypto_priv_key.to_vec().expect("Failed to export RSA Key");

    // Get unwrapping key pair for wrapping/unwrapping
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    // Wrap the generated key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    // Define properties for the unwrapped key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build private key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap the key pair into HSM
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (original_priv_key, original_pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

    // Get the masked key from the unwrapped private key
    let masked_key_pair = original_priv_key
        .masked_key_vec()
        .expect("Failed to get masked private key");

    // Unmask the key pair
    let mut unmask_algo = HsmRsaKeyUnmaskAlgo::default();
    let (unmasked_priv_key, unmasked_pub_key) =
        HsmKeyManager::unmask_key_pair(session, &mut unmask_algo, &masked_key_pair)
            .expect("Failed to unmask RSA key pair");

    // Verify all properties match between original (unwrapped) and unmasked keys
    compare_rsa_private_key_properties(&original_priv_key, &unmasked_priv_key);
    compare_rsa_public_key_properties(&original_pub_key, &unmasked_pub_key);

    HsmKeyManager::delete_key(original_priv_key).expect("Failed to delete original private key");
    HsmKeyManager::delete_key(original_pub_key).expect("Failed to delete original public key");
    HsmKeyManager::delete_key(unmasked_priv_key).expect("Failed to delete unmasked private key");
    HsmKeyManager::delete_key(unmasked_pub_key).expect("Failed to delete unmasked public key");
}

/// Helper to validate RSA unwrap functional correctness via encrypt/decrypt roundtrip
fn run_rsa_functional_test(
    session: &HsmSession,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    use crypto::*;

    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    let msg = b"rsa functional";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ct = HsmEncrypter::encrypt_vec(&mut algo, &pub_key, msg).unwrap();
    let pt = HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ct).unwrap();

    assert_eq!(pt, msg);

    HsmKeyManager::delete_key(priv_key).unwrap();
    HsmKeyManager::delete_key(pub_key).unwrap();
}

/// Helper to verify wrong unwrapping key produces different key material
fn run_rsa_wrong_key_test(session: &HsmSession, bits: u32, key_size_bytes: usize, salt_len: usize) {
    use crypto::*;

    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv_1, unwrap_pub_1) = get_rsa_unwrapping_key_pair(session);
    let (unwrap_priv_2, _) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub_1, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (good_priv, _) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv_1,
        &wrapped,
        priv_props.clone(),
        pub_props.clone(),
    )
    .unwrap();

    let (bad_priv, _) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv_2,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    let good_mask = good_priv.masked_key_vec().unwrap();
    let bad_mask = bad_priv.masked_key_vec().unwrap();

    assert_ne!(
        good_mask, bad_mask,
        "Wrong key should produce different key"
    );

    HsmKeyManager::delete_key(good_priv).unwrap();
    HsmKeyManager::delete_key(bad_priv).unwrap();
}

/// Helper to verify repeated unwrap produces usable (not necessarily identical) keys
fn run_rsa_repeatability_test(
    session: &HsmSession,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    use crypto::*;

    let crypto_priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = crypto_priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (k1_priv, k1_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props.clone(),
        pub_props.clone(),
    )
    .unwrap();

    let (k2_priv, k2_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .unwrap();

    let msg = b"repeatability";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ct1 = HsmEncrypter::encrypt_vec(&mut algo, &k1_pub, msg).unwrap();
    let pt1 = HsmDecrypter::decrypt_vec(&mut algo, &k1_priv, &ct1).unwrap();

    let ct2 = HsmEncrypter::encrypt_vec(&mut algo, &k2_pub, msg).unwrap();
    let pt2 = HsmDecrypter::decrypt_vec(&mut algo, &k2_priv, &ct2).unwrap();

    assert_eq!(pt1, msg);
    assert_eq!(pt2, msg);

    HsmKeyManager::delete_key(k1_priv).unwrap();
    HsmKeyManager::delete_key(k1_pub).unwrap();
    HsmKeyManager::delete_key(k2_priv).unwrap();
    HsmKeyManager::delete_key(k2_pub).unwrap();
}

/// Helper to verify truncated wrapped key fails during unwrap
fn run_rsa_truncated_ciphertext_test(
    session: &HsmSession,
    bits: u32,
    key_size_bytes: usize,
    salt_len: usize,
) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(key_size_bytes).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, salt_len);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    wrapped.truncate(wrapped.len() / 2);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(bits)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Truncated ciphertext should fail");
}

// ============================================================
// test case section
// ============================================================

/// Ensure RSA unwrapping key pair is generated with correct properties
#[session_test]
fn test_generate_unwrapping_key(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    // Verify private key properties
    assert_eq!(
        priv_key.class(),
        HsmKeyClass::Private,
        "Private key class mismatch"
    );
    assert_eq!(
        priv_key.kind(),
        HsmKeyKind::Rsa,
        "Private key kind mismatch"
    );
    assert_eq!(priv_key.bits(), 2048, "Private key bits mismatch");
    assert!(
        priv_key.is_local(),
        "Generated RSA private key should be local"
    );
    assert!(
        !priv_key.is_session(),
        "Private key should not be a session key"
    );
    assert!(
        priv_key.is_sensitive(),
        "Generated RSA private key should be sensitive"
    );
    assert!(
        priv_key.is_extractable(),
        "Generated RSA keys should be extractable"
    );
    assert!(
        !priv_key.can_sign(),
        "Private key should not support signing"
    );
    assert!(
        !priv_key.can_decrypt(),
        "Private key should not support decryption"
    );
    assert!(
        priv_key.can_unwrap(),
        "Private key should support unwrapping"
    );
    assert!(
        priv_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );

    // Verify public key properties
    assert_eq!(
        pub_key.class(),
        HsmKeyClass::Public,
        "Public key class mismatch"
    );
    assert_eq!(pub_key.kind(), HsmKeyKind::Rsa, "Public key kind mismatch");
    assert_eq!(pub_key.bits(), 2048, "Public key bits mismatch");
    assert!(
        pub_key.is_local(),
        "Generated RSA public key should be marked as local"
    );
    assert!(
        !pub_key.is_session(),
        "Public key should not be a session key"
    );
    assert!(
        !pub_key.is_sensitive(),
        "Public key should not be sensitive"
    );
    assert!(pub_key.is_extractable(), "Keys are always extractable");
    assert!(
        !pub_key.can_verify(),
        "Public key should not support verification"
    );
    assert!(
        !pub_key.can_encrypt(),
        "Public key should not support encryption"
    );
    assert!(pub_key.can_wrap(), "Public key should support wrapping");
    assert!(
        pub_key.ecc_curve().is_none(),
        "RSA key should not have ECC curve"
    );
}

/// Ensure RSA unwrap succeeds for 2048-bit key
#[session_test]
fn test_unwrap_rsa_2048_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 2048, 256, 32);
}

/// Ensure RSA unwrap succeeds for 3072-bit key
#[session_test]
fn test_unwrap_rsa_3072_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 3072, 384, 24);
}

/// Ensure RSA unwrap succeeds for 4096-bit key
#[session_test]
fn test_unwrap_rsa_4096_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 4096, 512, 16);
}

/// Ensure RSA unmask works correctly for 2048-bit key
#[session_test]
fn test_rsa_2048_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 2048, 256, 32);
}

/// Ensure RSA unmask works correctly for 3072-bit key
#[session_test]
fn test_rsa_3072_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 3072, 384, 24);
}

/// Ensure RSA unmask works correctly for 4096-bit key
#[session_test]
fn test_rsa_4096_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 4096, 512, 16);
}

/// Ensure key report generation works for imported RSA key
#[session_test]
fn test_rsa_2048_imported_key_report(session: HsmSession) {
    use crypto::*;

    // Generate RSA key using azihsm_crypto
    let priv_key = crypto::RsaPrivateKey::generate(256).expect("Failed to generate RSA Key");
    let der = priv_key.to_vec().expect("Failed to export RSA Key");

    // Get unwrapping key pair
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    // Wrap the generated key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &der)
        .expect("Failed to wrap RSA Key");

    // Define properties for the unwrapped key
    let priv_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build unwrapping key props");

    let pub_key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap the key pair (this is the "imported" key)
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        priv_key_props,
        pub_key_props,
    )
    .expect("Failed to unwrap RSA Key");

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
    HsmKeyManager::delete_key(priv_key).expect("Failed to delete RSA private key");
    HsmKeyManager::delete_key(pub_key).expect("Failed to delete RSA public key");
}

/// Ensure unwrap fails when bits do not match actual key size
#[session_test]
fn test_unwrap_rsa_wrong_bits_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap(); // 2048
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    // wrong bits (expect 2048 but give 3072)
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(3072)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Unwrap should fail for mismatched bits");
}

/// Ensure unwrap fails when wrapped key is corrupted
#[session_test]
fn test_unwrap_rsa_tampered_ciphertext(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    // corrupt ciphertext
    wrapped[0] ^= 0xFF;

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Unwrap should fail for tampered data");
}

/// Ensure unwrap fails if required capability missing
#[session_test]
fn test_unwrap_rsa_missing_capability(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    //  missing can_decrypt
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        result.is_err(),
        "Unwrap should fail without required capability"
    );
}

/// Ensure unwrapped RSA key can correctly encrypt/decrypt data
#[session_test]
fn test_unwrap_rsa_functional_correctness(session: HsmSession) {
    use crypto::*;

    // Generate external RSA key
    let crypto_priv_key = RsaPrivateKey::generate(256).expect("Failed to generate RSA key");
    let der = crypto_priv_key.to_vec().expect("Failed to export RSA key");

    // HSM unwrapping key pair
    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    // Wrap key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der)
        .expect("Failed to wrap RSA key");

    // Props
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .expect("Failed to build private key props");

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .expect("Failed to build public key props");

    // Unwrap
    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let (priv_key, pub_key) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    )
    .expect("Failed to unwrap RSA key");

    // ---- Functional test ----

    let plaintext = b"rsa functional test";

    //  Use correct constructor
    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    // Encrypt
    let ciphertext =
        HsmEncrypter::encrypt_vec(&mut algo, &pub_key, plaintext).expect("Encryption failed");

    // Decrypt (same algo type!)
    let decrypted =
        HsmDecrypter::decrypt_vec(&mut algo, &priv_key, &ciphertext).expect("Decryption failed");

    assert_eq!(plaintext.to_vec(), decrypted, "RSA roundtrip failed");

    HsmKeyManager::delete_key(priv_key).unwrap();
    HsmKeyManager::delete_key(pub_key).unwrap();
}

/// Ensure wrong unwrapping key produces DIFFERENT key material
#[session_test]
fn test_unwrap_rsa_wrong_key_differs(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv_1, unwrap_pub_1) = get_rsa_unwrapping_key_pair(&session);
    let (unwrap_priv_2, _) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub_1, &der).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (good_priv, _) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv_1,
        &wrapped,
        props.clone(),
        pub_props.clone(),
    )
    .unwrap();

    let (bad_priv, _) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv_2,
        &wrapped,
        props,
        pub_props,
    )
    .unwrap();

    let good_mask = good_priv.masked_key_vec().unwrap();
    let bad_mask = bad_priv.masked_key_vec().unwrap();

    //  This is the ONLY reliable invariant
    assert_ne!(
        good_mask, bad_mask,
        "Wrong key should produce different key material"
    );

    HsmKeyManager::delete_key(good_priv).unwrap();
    HsmKeyManager::delete_key(bad_priv).unwrap();
}

/// Ensure repeated unwrap produces usable keys (not necessarily identical)
#[session_test]
fn test_unwrap_rsa_repeatability(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let (k1_priv, k1_pub) = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        props.clone(),
        pub_props.clone(),
    )
    .unwrap();

    let (k2_priv, k2_pub) =
        HsmKeyManager::unwrap_key_pair(&mut unwrap_algo, &unwrap_priv, &wrapped, props, pub_props)
            .unwrap();

    // ✅ Validate both keys actually work
    let msg = b"repeatability test";

    let mut algo = HsmRsaEncryptAlgo::with_oaep_padding(HsmHashAlgo::Sha256, None);

    let ct1 = HsmEncrypter::encrypt_vec(&mut algo, &k1_pub, msg).unwrap();
    let pt1 = HsmDecrypter::decrypt_vec(&mut algo, &k1_priv, &ct1).unwrap();

    let ct2 = HsmEncrypter::encrypt_vec(&mut algo, &k2_pub, msg).unwrap();
    let pt2 = HsmDecrypter::decrypt_vec(&mut algo, &k2_priv, &ct2).unwrap();

    assert_eq!(pt1, msg);
    assert_eq!(pt2, msg);

    HsmKeyManager::delete_key(k1_priv).unwrap();
    HsmKeyManager::delete_key(k1_pub).unwrap();
    HsmKeyManager::delete_key(k2_priv).unwrap();
    HsmKeyManager::delete_key(k2_pub).unwrap();
}

/// Ensure unwrap fails when input ciphertext is empty
#[session_test]
fn test_unwrap_rsa_empty_input_fails(session: HsmSession) {
    let (unwrap_priv, _) = get_rsa_unwrapping_key_pair(&session);

    let wrapped = vec![]; // ❗ empty

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Empty input should fail");
}

/// Ensure unwrap fails when ciphertext is truncated
#[session_test]
fn test_unwrap_rsa_truncated_ciphertext_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    // ❗ truncate instead of flip
    wrapped.truncate(wrapped.len() / 2);

    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Truncated ciphertext should fail");
}

/// Ensure functional RSA unwrap works for 2048-bit key
#[session_test]
fn test_rsa_functional_2048(session: HsmSession) {
    run_rsa_functional_test(&session, 2048, 256, 32);
}

/// Ensure functional RSA unwrap works for 3072-bit key
#[session_test]
fn test_rsa_functional_3072(session: HsmSession) {
    run_rsa_functional_test(&session, 3072, 384, 24);
}

/// Ensure functional RSA unwrap works for 4096-bit key
#[session_test]
fn test_rsa_functional_4096(session: HsmSession) {
    run_rsa_functional_test(&session, 4096, 512, 16);
}

/// Ensure wrong unwrapping key differs for 2048-bit RSA
#[session_test]
fn test_rsa_wrong_key_2048(session: HsmSession) {
    run_rsa_wrong_key_test(&session, 2048, 256, 32);
}

/// Ensure wrong unwrapping key differs for 3072-bit RSA
#[session_test]
fn test_rsa_wrong_key_3072(session: HsmSession) {
    run_rsa_wrong_key_test(&session, 3072, 384, 24);
}

/// Ensure wrong unwrapping key differs for 4096-bit RSA
#[session_test]
fn test_rsa_wrong_key_4096(session: HsmSession) {
    run_rsa_wrong_key_test(&session, 4096, 512, 16);
}

/// Ensure unwrap repeatability for 2048-bit RSA
#[session_test]
fn test_rsa_repeatability_2048(session: HsmSession) {
    run_rsa_repeatability_test(&session, 2048, 256, 32);
}

/// Ensure unwrap repeatability for 3072-bit RSA
#[session_test]
fn test_rsa_repeatability_3072(session: HsmSession) {
    run_rsa_repeatability_test(&session, 3072, 384, 24);
}

/// Ensure unwrap repeatability for 4096-bit RSA
#[session_test]
fn test_rsa_repeatability_4096(session: HsmSession) {
    run_rsa_repeatability_test(&session, 4096, 512, 16);
}

/// Ensure truncated ciphertext fails unwrap for 2048-bit RSA
#[session_test]
fn test_rsa_truncated_2048(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, 2048, 256, 32);
}

/// Ensure truncated ciphertext fails unwrap for 3072-bit RSA
#[session_test]
fn test_rsa_truncated_3072(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, 3072, 384, 24);
}

/// Ensure truncated ciphertext fails unwrap for 4096-bit RSA
#[session_test]
fn test_rsa_truncated_4096(session: HsmSession) {
    run_rsa_truncated_ciphertext_test(&session, 4096, 512, 16);
}

/// Ensure unwrap fails when key kind is incorrect
#[session_test]
fn test_unwrap_rsa_wrong_key_kind_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    //  wrong key kind
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Public)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(result.is_err(), "Unwrap should fail for wrong key kind");
}

/// Ensure unwrap fails when key class combination is invalid
#[session_test]
fn test_unwrap_rsa_wrong_class_fails(session: HsmSession) {
    use crypto::*;

    let priv_key = RsaPrivateKey::generate(256).unwrap();
    let der = priv_key.to_vec().unwrap();

    let (unwrap_priv, unwrap_pub) = get_rsa_unwrapping_key_pair(&session);

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrap_pub, &der).unwrap();

    //  wrong: both private
    let priv_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private)
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_decrypt(true)
        .build()
        .unwrap();

    let pub_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Private) // ❌ should be Public
        .key_kind(HsmKeyKind::Rsa)
        .bits(2048)
        .can_encrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmRsaKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key_pair(
        &mut unwrap_algo,
        &unwrap_priv,
        &wrapped,
        priv_props,
        pub_props,
    );

    assert!(
        result.is_err(),
        "Unwrap should fail for wrong class combination"
    );
}
