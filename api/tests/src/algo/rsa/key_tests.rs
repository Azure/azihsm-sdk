// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_crypto as crypto;

use super::*;

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

// Tests

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

#[session_test]
fn test_unwrap_rsa_2048_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 2048, 256, 32);
}

#[session_test]
fn test_unwrap_rsa_3072_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 3072, 384, 24);
}

#[session_test]
fn test_unwrap_rsa_4096_key(session: HsmSession) {
    test_unwrap_rsa_key_for_bits(&session, 4096, 512, 16);
}

#[session_test]
fn test_rsa_2048_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 2048, 256, 32);
}

#[session_test]
fn test_rsa_3072_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 3072, 384, 24);
}

#[session_test]
fn test_rsa_4096_key_unmask(session: HsmSession) {
    test_rsa_key_unmask_for_bits(&session, 4096, 512, 16);
}
