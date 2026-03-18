// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::Rng;

use super::*;

// ================================
// Helpers
// ================================

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

    let (priv_key, pub_key) =
        HsmKeyManager::generate_key_pair(session, &mut algo, priv_key_props, pub_key_props)
            .expect("Failed to generate unwrapping key");

    (priv_key, pub_key)
}

fn verify_generated_aes_key_properties(key: &HsmAesKey, bits: u32, is_session: bool) {
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), bits, "Key bits mismatch");
    assert!(key.is_local(), "Session key should be local");
    assert_eq!(key.is_session(), is_session, "Session flag mismatch");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");
}

fn verify_unwrapped_aes_key_properties(key: &HsmAesKey, bits: u32, is_session: bool) {
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), bits, "Key bits mismatch");
    assert!(!key.is_local(), "Unwrapped key should not be local");
    assert_eq!(key.is_session(), is_session, "Session flag mismatch");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");
}

fn compare_key_properties(original: &HsmAesKey, unmasked: &HsmAesKey) {
    assert_eq!(original.class(), unmasked.class(), "Key class mismatch");
    assert_eq!(original.kind(), unmasked.kind(), "Key kind mismatch");
    assert_eq!(original.bits(), unmasked.bits(), "Key bits mismatch");
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Decrypt capability mismatch"
    );
    assert_eq!(
        original.can_sign(),
        unmasked.can_sign(),
        "Sign capability mismatch"
    );
    assert_eq!(
        original.can_verify(),
        unmasked.can_verify(),
        "Verify capability mismatch"
    );
    assert_eq!(
        original.can_unwrap(),
        unmasked.can_unwrap(),
        "Unwrap capability mismatch"
    );
    assert_eq!(
        original.can_derive(),
        unmasked.can_derive(),
        "Derive capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Extractable flag mismatch"
    );
}

fn compare_xts_key_properties(original: &HsmAesXtsKey, unmasked: &HsmAesXtsKey) {
    assert_eq!(original.class(), unmasked.class(), "Key class mismatch");
    assert_eq!(original.kind(), unmasked.kind(), "Key kind mismatch");
    assert_eq!(original.bits(), unmasked.bits(), "Key bits mismatch");
    assert_eq!(
        original.can_encrypt(),
        unmasked.can_encrypt(),
        "Encrypt capability mismatch"
    );
    assert_eq!(
        original.can_decrypt(),
        unmasked.can_decrypt(),
        "Decrypt capability mismatch"
    );
    assert_eq!(
        original.is_session(),
        unmasked.is_session(),
        "Session flag mismatch"
    );
    assert_eq!(
        original.is_local(),
        unmasked.is_local(),
        "Local flag mismatch"
    );
    assert_eq!(
        original.is_sensitive(),
        unmasked.is_sensitive(),
        "Sensitive flag mismatch"
    );
    assert_eq!(
        original.is_extractable(),
        unmasked.is_extractable(),
        "Extractable flag mismatch"
    );
}

fn test_session_aes_key_generation_common(session: &HsmSession, bits: u32) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut algo = HsmAesKeyGenAlgo::default();
    let key =
        HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key");

    verify_generated_aes_key_properties(&key, bits, true);
    HsmKeyManager::delete_key(key).expect("Failed to delete AES key");
}

fn test_aes_key_unwrap_common(session: &HsmSession, bits: u32, is_session: bool) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(session);

    let key_bytes = (bits / 8) as usize;
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);
    let aes_key_data = vec![0u8; key_bytes];
    let wrapped_key = HsmEncrypter::encrypt_vec(&mut wrap_algo, &unwrapping_pub_key, &aes_key_data)
        .expect("Failed to wrap AES Key");

    let mut builder = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true);

    if is_session {
        builder = builder.is_session(true);
    }

    let key_props = builder.build().expect("Failed to build key props");

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let aes_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_key,
        key_props,
    )
    .expect("Failed to unwrap AES Key");

    verify_unwrapped_aes_key_properties(&aes_key, bits, is_session);
    HsmKeyManager::delete_key(aes_key).expect("Failed to delete unwrapped AES key");
}

fn test_aes_key_unmask_common(session: &HsmSession, bits: u32) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(bits)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let original_key = HsmKeyManager::generate_key(session, &mut gen_algo, props)
        .expect("Failed to generate AES key");

    let masked_key = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    let mut unmask_algo = HsmAesKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(session, &mut unmask_algo, &masked_key)
        .expect("Failed to unmask AES key");

    compare_key_properties(&original_key, &unmasked_key);
    HsmKeyManager::delete_key(unmasked_key).expect("Failed to delete unmasked AES key");
    HsmKeyManager::delete_key(original_key).expect("Failed to delete original AES key");
}

fn build_xts_wrapped_blob_header(key1_len: u16, key2_len: u16) -> [u8; 16] {
    // Keep tests agnostic to the internal Rust header struct.
    // On-wire header format:
    // magic (u64 LE) + version (u16 LE) + key1_len (u16 LE) + key2_len (u16 LE) + reserved (u16 LE)
    const WRAP_BLOB_MAGIC: u64 = 0x5354_584D_5348_5A41;
    const WRAP_BLOB_VERSION: u16 = 1;

    let mut hdr = [0u8; 16];
    hdr[0..8].copy_from_slice(&WRAP_BLOB_MAGIC.to_le_bytes());
    hdr[8..10].copy_from_slice(&WRAP_BLOB_VERSION.to_le_bytes());
    hdr[10..12].copy_from_slice(&key1_len.to_le_bytes());
    hdr[12..14].copy_from_slice(&key2_len.to_le_bytes());
    // reserved already zero
    hdr
}

fn build_xts_wrapped_blob(
    wrapping_pub_key: &HsmRsaPublicKey,
    hash: HsmHashAlgo,
    key1_plain: &[u8],
    key2_plain: &[u8],
) -> Vec<u8> {
    let mut wrap_algo_1 = HsmRsaAesWrapAlgo::new(hash, key1_plain.len());
    let key1_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_1, wrapping_pub_key, key1_plain)
        .expect("Failed to wrap XTS key1");

    let mut wrap_algo_2 = HsmRsaAesWrapAlgo::new(hash, key2_plain.len());
    let key2_wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo_2, wrapping_pub_key, key2_plain)
        .expect("Failed to wrap XTS key2");

    let key1_len = u16::try_from(key1_wrapped.len()).unwrap();
    let key2_len = u16::try_from(key2_wrapped.len()).unwrap();
    let header = build_xts_wrapped_blob_header(key1_len, key2_len);

    let mut blob = Vec::with_capacity(header.len() + key1_wrapped.len() + key2_wrapped.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&key1_wrapped);
    blob.extend_from_slice(&key2_wrapped);
    blob
}

// Validate the unwrapped key is usable for AES-XTS encryption/decryption.

fn tweak_after_units(tweak: &[u8; 16], units: usize) -> [u8; 16] {
    u128::from_le_bytes(*tweak)
        .checked_add(units as u128)
        .expect("tweak increment overflow")
        .to_le_bytes()
}

fn test_iv(size: usize) -> Vec<u8> {
    Rng::rand_vec(size).expect("RNG failure generating IV")
}

// ================================
// AES Key Tests
// ================================

/// Test AES key generation.
///
/// Verifies that an AES-256  key can be successfully generated within
/// an HSM session with encrypt and decrypt capabilities.
#[session_test]
fn test_token_aes_key_generation(session: HsmSession) {
    // Create key properties for a 256-bit AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES key");

    // Verify key properties
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::Aes, "Key kind mismatch");
    assert_eq!(key.bits(), 256, "Key bits mismatch");
    assert!(key.is_local(), "Token key should be local");
    assert!(!key.is_session(), "Token key should not be a session key");
    assert!(key.is_sensitive(), "Secret key should be sensitive");
    assert!(key.is_extractable(), "Keys are always extractable");
    assert!(key.can_encrypt(), "Key should support encryption");
    assert!(key.can_decrypt(), "Key should support decryption");
    assert!(!key.can_sign(), "Key should not support signing");
    assert!(!key.can_verify(), "Key should not support verification");
    assert!(!key.can_unwrap(), "Key should not support unwrapping");
    assert!(!key.can_derive(), "Key should not support derivation");

    // Clean up: delete the key from the HSM
    HsmKeyManager::delete_key(key).expect("Failed to delete AES-CBC key");
}

/// Test AES key generation for key sizes of 128
#[session_test]
fn test_session_aes_128_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 128);
}

/// Test AES key generation for key sizes of 192
#[session_test]
fn test_session_aes_192_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 192);
}

/// Test AES key generation for key sizes of 256    
#[session_test]
fn test_session_aes_256_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 256);
}

/// Test AES key unwrapping for key sizes of 128
#[session_test]
fn test_aes_128_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 128, false);
}

/// Test AES key unwrapping for key sizes of 192
#[session_test]
fn test_aes_192_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 192, false);
}

/// Test AES key unwrapping for key sizes of 256
#[session_test]
fn test_aes_256_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 256, true);
}

/// Test AES key unmasking for key sizes of 128
#[session_test]
fn test_aes_128_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 128);
}

/// Test AES key unmasking for key sizes of 192
#[session_test]
fn test_aes_192_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 192);
}

/// Test AES key unmasking for key sizes of 256
#[session_test]
fn test_aes_256_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 256);
}

/// verifies AES key unwrap fails when wrapped blob is corrupted
#[session_test]
fn test_aes_key_unwrap_corrupted_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let aes_key = vec![0x55u8; key_bytes];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);

    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key)
        .expect("Failed to wrap AES key");

    wrapped[0] ^= 0xFF; // corrupt

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES key unmask fails when unmasking with corrupted masked blob
#[session_test]
fn test_aes_unmask_corrupted_blob_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let mut masked = key.masked_key_vec().unwrap();
    masked[0] ^= 0xFF; // corrupt

    let mut algo = HsmAesKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES key unwrap fails when unwrapping with wrong algorithm type
#[session_test]
fn test_aes_unwrap_wrong_algo_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let aes_key = vec![0x11u8; key_bytes];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    // wrong unwrap algorithm
    let mut wrong_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut wrong_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES key unmasking produces a usable key that can encrypt and decrypt,
/// and that the unmasked key is independent of the original key by deleting the
/// original key before using the unmasked key
#[session_test]
fn test_aes_unmasked_key_independent_handle(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let original = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let masked = original.masked_key_vec().unwrap();

    let mut unmask_algo = HsmAesKeyUnmaskAlgo::default();
    let unmasked = HsmKeyManager::unmask_key(&session, &mut unmask_algo, &masked).unwrap();

    // delete original first
    HsmKeyManager::delete_key(original).unwrap();

    // unmasked key should still work
    let plaintext = vec![0x11u8; 32];

    let mut enc_algo = HsmAesCbcAlgo::with_padding(test_iv(16)).unwrap();
    let len = HsmEncrypter::encrypt(&mut enc_algo, &unmasked, &plaintext, None).unwrap();
    let mut out = vec![0u8; len];

    let result = HsmEncrypter::encrypt(&mut enc_algo, &unmasked, &plaintext, Some(&mut out));

    assert!(result.is_ok());

    HsmKeyManager::delete_key(unmasked).unwrap();
}

/// verifies AES key unwrap fails when unwrapping with truncated wrapped blob   
#[session_test]
fn test_aes_unwrap_truncated_blob_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let aes_key = vec![0x11u8; 32];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);

    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    // truncate blob
    wrapped.truncate(wrapped.len() - 8);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_with_sign_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_sign(true) // invalid for AES
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject sign capability"
    );
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_with_verify_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_verify(true) // invalid
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject verify capability"
    );
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_with_wrap_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_wrap(true) // invalid
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject wrap capability"
    );
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_with_unwrap_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_unwrap(true) // invalid
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject unwrap capability"
    );
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_with_derive_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_derive(true) // invalid
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject derive capability"
    );
}

/// verifies AES key generation fails when multiple unsupported capabilities are set
/// in properties
#[session_test]
fn test_aes_key_gen_multiple_invalid_flags_fail(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .can_sign(true)
        .can_wrap(true)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject unsupported capability combinations"
    );
}

/// verifies AES key generation rejects keys with only unsupported capabilities
#[session_test]
fn test_aes_key_gen_only_invalid_capabilities(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_verify(true)
        .can_wrap(true)
        .can_unwrap(true)
        .can_derive(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject unsupported capability-only keys"
    );
}

/// verifies invalid flags are rejected even if encrypt/decrypt permissions are missing
#[session_test]
fn test_aes_key_gen_invalid_flags_without_crypto_permissions(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_sign(true)
        .can_wrap(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        matches!(result, Err(HsmError::InvalidKeyProps)),
        "AES key generation should reject invalid flags even without encrypt/decrypt"
    );
}

/// verifies AES key generation rejects combinations of unsupported capability flags
#[session_test]
fn test_aes_key_gen_multiple_invalid_capabilities(session: HsmSession) {
    let invalid_flag_sets = [
        (true, false, false, false, false), // sign
        (false, true, false, false, false), // verify
        (false, false, true, false, false), // wrap
        (false, false, false, true, false), // unwrap
        (false, false, false, false, true), // derive
        (true, true, false, false, false),
        (true, false, true, false, false),
        (true, false, false, true, false),
        (true, false, false, false, true),
        (false, true, true, false, false),
        (false, true, false, true, false),
        (false, true, false, false, true),
        (false, false, true, true, false),
        (false, false, true, false, true),
        (false, false, false, true, true),
        (true, true, true, true, true),
    ];

    for (sign, verify, wrap, unwrap, derive) in invalid_flag_sets {
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::Aes)
            .bits(256)
            .can_encrypt(true)
            .can_decrypt(true)
            .can_sign(sign)
            .can_verify(verify)
            .can_wrap(wrap)
            .can_unwrap(unwrap)
            .can_derive(derive)
            .is_session(true)
            .build()
            .unwrap();

        let mut algo = HsmAesKeyGenAlgo::default();

        let result = HsmKeyManager::generate_key(&session, &mut algo, props);

        assert!(
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "AES key generation should reject invalid capability combination: \
             sign={sign}, verify={verify}, wrap={wrap}, unwrap={unwrap}, derive={derive}"
        );
    }
}

/// verifies AES key generation fails when unsupported capabilities are set in properties
#[session_test]
fn test_aes_key_gen_no_decrypt_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(false)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES key generation should fail without decrypt permission"
    );
}

/// verifies AES key unwrap fails when unwrapping with mismatched bits in properties
#[session_test]
fn test_aes_unwrap_bits_mismatch_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let aes_key = vec![0x11u8; 32]; // 256-bit

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);

    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(128) // wrong size
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES-GCM unwrap fails when wrapped blob is truncated
#[session_test]
fn test_aes_unmask_wrong_kind_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let masked = key.masked_key_vec().unwrap();

    let mut wrong_unmask_algo = HsmAesGcmKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut wrong_unmask_algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-CBC decryption fails when ciphertext padding is corrupted
#[session_test]
fn test_aes_cbc_invalid_padding_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let plaintext = vec![0x11u8; 32];

    // Generate IV once
    let iv = test_iv(16);

    // --- Encrypt ---
    let mut enc_algo = HsmAesCbcAlgo::with_padding(iv.clone()).unwrap();

    let cipher_len = HsmEncrypter::encrypt(&mut enc_algo, &key, &plaintext, None).unwrap();
    let mut ciphertext = vec![0u8; cipher_len];

    let written =
        HsmEncrypter::encrypt(&mut enc_algo, &key, &plaintext, Some(&mut ciphertext)).unwrap();

    ciphertext.truncate(written);

    // Deterministically corrupt padding by mutating C[n-1][-1].
    // For plaintext length 32, PKCS#7 pad length is 16 (0x10).
    // Flipping C[n-1][-1] with XOR 0x01 flips P[n][-1] to 0x11 (> block size),
    // which is always invalid and avoids the flake from mutating C[n][-1].
    let prev_block_last_index = ciphertext
        .len()
        .checked_sub(17)
        .expect("ciphertext too short for deterministic padding corruption");
    ciphertext[prev_block_last_index] ^= 0x01;

    // --- Decrypt ---
    let mut dec_algo = HsmAesCbcAlgo::with_padding(iv).unwrap();

    let plain_len = HsmDecrypter::decrypt(&mut dec_algo, &key, &ciphertext, None).unwrap();
    let mut out = vec![0u8; plain_len];

    let result = HsmDecrypter::decrypt(&mut dec_algo, &key, &ciphertext, Some(&mut out));

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-CBC decryption fails when decrypting with the wrong key
#[session_test]
fn test_aes_cbc_wrong_key_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();

    let key1 = HsmKeyManager::generate_key(&session, &mut algo, props.clone()).unwrap();
    let key2 = HsmKeyManager::generate_key(&session, &mut algo, props).unwrap();

    let plaintext = vec![0x11u8; 32];

    // Generate IV once
    let iv = test_iv(16);

    let mut enc = HsmAesCbcAlgo::with_padding(iv.clone()).unwrap();

    let len = HsmEncrypter::encrypt(&mut enc, &key1, &plaintext, None).unwrap();
    let mut ciphertext = vec![0u8; len];

    HsmEncrypter::encrypt(&mut enc, &key1, &plaintext, Some(&mut ciphertext)).unwrap();

    let mut dec = HsmAesCbcAlgo::with_padding(iv).unwrap();

    let plain_len = HsmDecrypter::decrypt(&mut dec, &key2, &ciphertext, None).unwrap();
    let mut out = vec![0u8; plain_len];

    let result = HsmDecrypter::decrypt(&mut dec, &key2, &ciphertext, Some(&mut out));

    assert!(result.is_err());

    HsmKeyManager::delete_key(key1).unwrap();
    HsmKeyManager::delete_key(key2).unwrap();
}

/// verifies AES-CBC encryption and decryption roundtrip using an unwrapped key
#[session_test]
fn test_aes_unwrapped_key_roundtrip(session: HsmSession) {
    // Generate RSA wrapping key pair
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    // AES key material
    let aes_key_material = vec![0x11u8; 32];

    // Wrap AES key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, aes_key_material.len());

    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key_material)
        .expect("AES key wrap failed");

    // AES key properties
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::Aes)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    // Unwrap AES key
    let mut unwrap_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let aes_key = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props)
        .expect("AES key unwrap failed");

    let plaintext = b"hello aes cbc".to_vec();

    // Generate IV once
    let iv = test_iv(16);

    // --- Encrypt ---
    let mut enc = HsmAesCbcAlgo::with_padding(iv.clone()).unwrap();

    let cipher_len = HsmEncrypter::encrypt(&mut enc, &aes_key, &plaintext, None)
        .expect("encrypt size query failed");

    let mut ciphertext = vec![0u8; cipher_len];

    let written = HsmEncrypter::encrypt(&mut enc, &aes_key, &plaintext, Some(&mut ciphertext))
        .expect("AES-CBC encryption failed");

    ciphertext.truncate(written);

    // --- Decrypt ---
    let mut dec = HsmAesCbcAlgo::with_padding(iv).unwrap();

    let plain_len = HsmDecrypter::decrypt(&mut dec, &aes_key, &ciphertext, None)
        .expect("decrypt size query failed");

    let mut decrypted = vec![0u8; plain_len];

    let written = HsmDecrypter::decrypt(&mut dec, &aes_key, &ciphertext, Some(&mut decrypted))
        .expect("AES-CBC decryption failed");

    decrypted.truncate(written);

    assert_eq!(plaintext, decrypted);

    let _ = HsmKeyManager::delete_key(aes_key);
}

// ================================
// AES XTS Tests
// ================================
/// verifies AES-XTS 512-bit key generation succeeds with correct properties and capabilities
#[session_test]
fn test_aes_xts_512_key_generation(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES XTS key");
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::AesXts, "Key kind mismatch");
    assert_eq!(key.bits(), 512, "Key bits mismatch");
    assert_eq!(key.can_encrypt(), true, "Key should support encryption");
    assert_eq!(key.can_decrypt(), true, "Key should support decryption");
}

/// verifies AES-XTS key generation rejects invalid key sizes and returns appropriate error
#[session_test]
fn test_aes_xts_key_generation_invalid_sizes_rejected(session: HsmSession) {
    // AES-XTS is only supported for 64-byte keys (512 bits).
    for bits in [0u32, 1, 128, 192, 256, 384, 511, 513, 1024] {
        let props = HsmKeyPropsBuilder::default()
            .class(HsmKeyClass::Secret)
            .key_kind(HsmKeyKind::AesXts)
            .bits(bits)
            .can_encrypt(true)
            .can_decrypt(true)
            .is_session(true)
            .build()
            .expect("Failed to build key props");

        let mut algo = HsmAesXtsKeyGenAlgo::default();
        let result = HsmKeyManager::generate_key(&session, &mut algo, props);
        assert!(
            matches!(result, Err(HsmError::InvalidKeyProps)),
            "XTS key generation should reject invalid key size {bits}"
        );
    }
}

/// Test AES-XTS key unwrapping, and validate the unwrapped key can be used for encryption and decryption with correct tweak handling. Also validates that the unwrapped key has expected properties and capabilities, and is not local to the session.
#[session_test]
fn test_aes_xts_key_unwrap(session: HsmSession) {
    let (unwrapping_priv_key, unwrapping_pub_key) = get_rsa_unwrapping_key_pair(&session);

    // AES-XTS uses two AES-256 keys (total bits=512).
    let key_bytes = 32;
    let key1_plain = vec![0x11u8; key_bytes];
    let key2_plain = vec![0x22u8; key_bytes];
    let wrapped_blob = build_xts_wrapped_blob(
        &unwrapping_pub_key,
        HsmHashAlgo::Sha256,
        &key1_plain,
        &key2_plain,
    );

    let key_props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .expect("Failed to build key props");

    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);
    let xts_key = HsmKeyManager::unwrap_key(
        &mut unwrap_algo,
        &unwrapping_priv_key,
        &wrapped_blob,
        key_props,
    )
    .expect("Failed to unwrap AES-XTS key");

    assert_eq!(xts_key.class(), HsmKeyClass::Secret);
    assert_eq!(xts_key.kind(), HsmKeyKind::AesXts);
    assert_eq!(xts_key.bits(), 512);
    assert!(xts_key.can_encrypt());
    assert!(xts_key.can_decrypt());
    assert!(!xts_key.is_local(), "Unwrapped XTS key should not be local");

    let tweak: [u8; 16] = [0u8; 16];
    let dul: usize = 64;
    let plaintext: Vec<u8> = vec![0x11u8; 128];
    assert_eq!(plaintext.len(), dul * 2);

    // One-shot encrypt of 2 data units.
    let mut enc_algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES-XTS algo");
    let out_len = enc_algo
        .encrypt(&xts_key, &plaintext, None)
        .expect("AES-XTS encrypt size query failed");
    assert_eq!(
        enc_algo.tweak(),
        tweak.to_vec(),
        "Size query must not mutate tweak"
    );
    let mut ciphertext_full = vec![0u8; out_len];
    let written = enc_algo
        .encrypt(&xts_key, &plaintext, Some(&mut ciphertext_full))
        .expect("AES-XTS encryption failed");
    ciphertext_full.truncate(written);
    assert_eq!(ciphertext_full.len(), plaintext.len());
    assert_ne!(
        ciphertext_full, plaintext,
        "Ciphertext should differ from plaintext"
    );
    assert_eq!(
        enc_algo.tweak(),
        tweak_after_units(&tweak, 2).to_vec(),
        "Encrypt should increment tweak per data unit"
    );

    // Encrypt per-data-unit with tweak and tweak+1; output should match one-shot.
    let (pt0, pt1) = plaintext.split_at(dul);
    let mut algo0 = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES-XTS algo");
    let mut ct0 = vec![0u8; algo0.encrypt(&xts_key, pt0, None).unwrap()];
    let written0 = algo0.encrypt(&xts_key, pt0, Some(&mut ct0)).unwrap();
    ct0.truncate(written0);

    let tweak1 = tweak_after_units(&tweak, 1);
    let mut algo1 = HsmAesXtsAlgo::new(&tweak1, dul).expect("Failed to create AES-XTS algo");
    let mut ct1 = vec![0u8; algo1.encrypt(&xts_key, pt1, None).unwrap()];
    let written1 = algo1.encrypt(&xts_key, pt1, Some(&mut ct1)).unwrap();
    ct1.truncate(written1);

    let mut ciphertext_split = Vec::with_capacity(ciphertext_full.len());
    ciphertext_split.extend_from_slice(&ct0);
    ciphertext_split.extend_from_slice(&ct1);
    assert_eq!(
        ciphertext_split, ciphertext_full,
        "Tweak increment mismatch"
    );

    // One-shot decrypt should restore plaintext and increment tweak similarly.
    let mut dec_algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES-XTS algo");
    let out_len = dec_algo
        .decrypt(&xts_key, &ciphertext_full, None)
        .expect("AES-XTS decrypt size query failed");
    assert_eq!(
        dec_algo.tweak(),
        tweak.to_vec(),
        "Size query must not mutate tweak"
    );
    let mut decrypted = vec![0u8; out_len];
    let written = dec_algo
        .decrypt(&xts_key, &ciphertext_full, Some(&mut decrypted))
        .expect("AES-XTS decryption failed");
    decrypted.truncate(written);
    assert_eq!(decrypted, plaintext, "Roundtrip plaintext mismatch");
    assert_eq!(
        dec_algo.tweak(),
        tweak_after_units(&tweak, 2).to_vec(),
        "Decrypt should increment tweak per data unit"
    );
}

/// Test AES-XTS key unmasking, and validate the unmasked key can be used for encryption
/// and decryption with correct tweak handling. Also validates that the unmasked key has
///  expected properties and capabilities, and is not local to the session.
#[session_test]
fn test_aes_xts_key_unmask(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut gen_algo = HsmAesXtsKeyGenAlgo::default();
    let original_key = HsmKeyManager::generate_key(&session, &mut gen_algo, props)
        .expect("Failed to generate AES-XTS key");

    // Encrypt with the original generated key, then unmask and decrypt with the unmasked key.
    let tweak: [u8; 16] = [0u8; 16];
    let dul: usize = 64;
    let plaintext: Vec<u8> = vec![0x33u8; 128];

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES-XTS algo");
    let out_len = algo
        .encrypt(&original_key, &plaintext, None)
        .expect("AES-XTS encrypt size query failed");
    let mut ciphertext = vec![0u8; out_len];
    let written = algo
        .encrypt(&original_key, &plaintext, Some(&mut ciphertext))
        .expect("AES-XTS encryption failed");
    ciphertext.truncate(written);

    let masked_key = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    let mut unmask_algo = HsmAesXtsKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(&session, &mut unmask_algo, &masked_key)
        .expect("Failed to unmask AES-XTS key");

    compare_xts_key_properties(&original_key, &unmasked_key);

    // Prove the unmasked key is a different key ID by deleting the original key
    // before using the unmasked key.
    HsmKeyManager::delete_key(original_key).expect("Failed to delete original AES-XTS key");

    let mut dec_algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES-XTS algo");
    let out_len = dec_algo
        .decrypt(&unmasked_key, &ciphertext, None)
        .expect("AES-XTS decrypt size query failed");
    let mut decrypted = vec![0u8; out_len];
    let written = dec_algo
        .decrypt(&unmasked_key, &ciphertext, Some(&mut decrypted))
        .expect("AES-XTS decryption failed");
    decrypted.truncate(written);

    assert_eq!(decrypted, plaintext, "XTS roundtrip mismatch");

    HsmKeyManager::delete_key(unmasked_key).expect("Failed to delete unmasked AES-XTS key");
}

/// verifies AES-XTS key unwrap fails when wrapped blob is corrupted
#[session_test]
fn test_aes_xts_key_unwrap_corrupted_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let key1 = vec![0x11u8; key_bytes];
    let key2 = vec![0x22u8; key_bytes];

    let mut blob = build_xts_wrapped_blob(&pub_key, HsmHashAlgo::Sha256, &key1, &key2);

    blob[0] ^= 0xFF; // corrupt header

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &blob, props);

    assert!(result.is_err());
}

/// verifies AES-XTS key unwrap fails when unwrapping with wrong algorithm type
#[session_test]
fn test_aes_xts_unwrap_wrong_algo_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let key1 = vec![0x11u8; key_bytes];
    let key2 = vec![0x22u8; key_bytes];

    let blob = build_xts_wrapped_blob(&pub_key, HsmHashAlgo::Sha256, &key1, &key2);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    // wrong unwrap algorithm
    let mut wrong_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut wrong_algo, &priv_key, &blob, props);

    assert!(result.is_err());
}

/// verifies AES-XTS key generation fails when decrypt permission is missing, since XTS mode
#[session_test]
fn test_aes_xts_key_gen_no_decrypt_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(false)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesXtsKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES-XTS key generation should fail without decrypt permission"
    );
}

/// verifies AES-XTS key unmasking fails when unmasking with corrupted masked blob
#[session_test]
fn test_aes_xts_unmask_corrupted_blob_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesXtsKeyGenAlgo::default();

    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let mut masked = key.masked_key_vec().unwrap();

    // corrupt masked blob
    masked[0] ^= 0xFF;

    let mut algo = HsmAesXtsKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-XTS key generation fails when encrypt permission is missing
#[session_test]
fn test_aes_xts_key_gen_no_encrypt_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(false)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesXtsKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES-XTS key generation should fail without encrypt permission"
    );
}

/// verifies AES key unmask fails when using the wrong unmask algorithm
#[session_test]
fn test_aes_xts_unmask_wrong_kind_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesXtsKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let masked = key.masked_key_vec().unwrap();

    let mut wrong_unmask_algo = HsmAesKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut wrong_unmask_algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-XTS unwrap fails when provided key size does not match wrapped key
#[session_test]
fn test_aes_xts_unwrap_bits_mismatch_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key1 = vec![0x11u8; 32];
    let key2 = vec![0x22u8; 32];

    let blob = build_xts_wrapped_blob(&pub_key, HsmHashAlgo::Sha256, &key1, &key2);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(256) // wrong size
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &blob, props);

    assert!(result.is_err());
}

/// verifies AES-XTS key unwrap fails when the wrapped blob is truncated
#[session_test]
fn test_aes_xts_unwrap_truncated_blob_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key1 = vec![0x11u8; 32];
    let key2 = vec![0x22u8; 32];

    let mut blob = build_xts_wrapped_blob(&pub_key, HsmHashAlgo::Sha256, &key1, &key2);

    blob.truncate(blob.len() - 8);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesXtsKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &blob, props);

    assert!(result.is_err());
}

// ================================
// AES GCM Tests
// ================================

/// Test AES-GCM key generation, and validate the generated key has expected properties
/// and capabilities.
#[session_test]
fn test_aes_gcm_256_key_generation(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key props");

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let key = HsmKeyManager::generate_key(&session, &mut algo, props)
        .expect("Failed to generate AES-GCM key");

    assert_eq!(key.class(), HsmKeyClass::Secret);
    assert_eq!(key.kind(), HsmKeyKind::AesGcm);
    assert_eq!(key.bits(), 256);
    assert!(key.can_encrypt());
    assert!(key.can_decrypt());

    HsmKeyManager::delete_key(key).expect("Failed to delete AES-GCM key");
}

/// Test AES-GCM key unmasking for a 256-bit key, and validate the unmasked key has expected
/// properties and capabilities, and matches the original key's properties.
#[session_test]
fn test_aes_gcm_256_key_unmask(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesGcmKeyGenAlgo::default();
    let original_key = HsmKeyManager::generate_key(&session, &mut gen_algo, props)
        .expect("Failed to generate AES-GCM key");

    let masked = original_key
        .masked_key_vec()
        .expect("Failed to get masked key");

    let mut unmask_algo = HsmAesGcmKeyUnmaskAlgo::default();
    let unmasked_key = HsmKeyManager::unmask_key(&session, &mut unmask_algo, &masked)
        .expect("Failed to unmask AES-GCM key");

    assert_eq!(original_key.kind(), unmasked_key.kind());
    assert_eq!(original_key.bits(), unmasked_key.bits());
    assert_eq!(original_key.class(), unmasked_key.class());

    HsmKeyManager::delete_key(unmasked_key).unwrap();
    HsmKeyManager::delete_key(original_key).unwrap();
}

/// verifies AES-GCM key can be unwrapped using RSA-AES wrapping
#[session_test]
fn test_aes_gcm_256_key_unwrap(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let aes_key = vec![0x11u8; key_bytes];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);

    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key)
        .expect("Failed to wrap AES-GCM key");

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let key = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props)
        .expect("Failed to unwrap AES-GCM key");

    assert_eq!(key.kind(), HsmKeyKind::AesGcm);
    assert_eq!(key.bits(), 256);

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-GCM key unwrap fails when wrapped blob is corrupted
#[session_test]
fn test_aes_gcm_256_key_unwrap_corrupted_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let aes_key = vec![0x22u8; key_bytes];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);

    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key)
        .expect("Failed to wrap AES-GCM key");

    // corrupt data
    wrapped[0] ^= 0xFF;

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES-GCM encryption and decryption roundtrip using an unwrapped key
#[session_test]
fn test_aes_gcm_unwrapped_key_roundtrip(session: HsmSession) {
    const IV_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    // Generate RSA wrapping key pair
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    // AES key material
    let aes_key_material = vec![0x11u8; 32];

    // Wrap AES key
    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, aes_key_material.len());

    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key_material)
        .expect("AES key wrap failed");

    // Correct AES-GCM key properties
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    // Unwrap AES key
    let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let aes_key = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props)
        .expect("AES key unwrap failed");

    let iv = [1u8; IV_SIZE];
    let plaintext = b"hello aes gcm".to_vec();

    // --- Encrypt ---
    let mut enc = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), None).unwrap();

    let cipher_len = HsmEncrypter::encrypt(&mut enc, &aes_key, &plaintext, None)
        .expect("encrypt size query failed");

    let mut ciphertext = vec![0u8; cipher_len];

    let written = HsmEncrypter::encrypt(&mut enc, &aes_key, &plaintext, Some(&mut ciphertext))
        .expect("AES-GCM encryption failed");

    ciphertext.truncate(written);

    let tag = enc.tag().expect("missing tag").to_vec();
    assert_eq!(tag.len(), TAG_SIZE);

    // --- Decrypt ---
    let mut dec = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag, None).unwrap();

    let plain_len = HsmDecrypter::decrypt(&mut dec, &aes_key, &ciphertext, None)
        .expect("decrypt size query failed");

    let mut decrypted = vec![0u8; plain_len];

    let written = HsmDecrypter::decrypt(&mut dec, &aes_key, &ciphertext, Some(&mut decrypted))
        .expect("AES-GCM decryption failed");

    decrypted.truncate(written);

    assert_eq!(plaintext, decrypted);

    let _ = HsmKeyManager::delete_key(aes_key);
}

/// verifies AES-GCM key unmask fails when unmasking with wrong algorithm type
#[session_test]
fn test_aes_gcm_unmask_wrong_kind_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesGcmKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let masked = key.masked_key_vec().unwrap();

    let mut wrong_unmask_algo = HsmAesKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut wrong_unmask_algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-GCM key unmask fails when unmasking with wrong algorithm type
#[session_test]
fn test_aes_gcm_key_gen_invalid_bits_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(128) // invalid for this generator
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES-GCM key generation should fail for invalid key size"
    );
}

/// verifies AES-GCM key generation fails when encrypt flag is not set
#[session_test]
fn test_aes_gcm_key_gen_no_encrypt_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(false)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES-GCM key generation should fail without encrypt permission"
    );
}

/// verifies AES-GCM key generation fails when decrypt flag is not set
#[session_test]
fn test_aes_gcm_key_gen_no_decrypt_flag_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(false)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let result = HsmKeyManager::generate_key(&session, &mut algo, props);

    assert!(
        result.is_err(),
        "AES-GCM key generation should fail without decrypt permission"
    );
}

/// verifies AES-GCM key generation with non-session persistence creates a non-session key
/// and succeeds with correct properties and capabilities
#[session_test]
fn test_aes_gcm_key_gen_persistent(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(false)
        .build()
        .unwrap();

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let key =
        HsmKeyManager::generate_key(&session, &mut algo, props).expect("Key generation failed");

    assert!(!key.is_session());

    let _ = HsmKeyManager::delete_key(key);
}

/// verifies AES-GCM key unwrap fails when unwrapping with wrong algorithm type
#[session_test]
fn test_aes_gcm_unwrap_wrong_algo_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let key_bytes = 32;
    let aes_key = vec![0x33u8; key_bytes];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, key_bytes);
    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    // wrong unwrap algo
    let mut wrong_algo = HsmAesKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut wrong_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES-GCM decryption fails when decrypting with wrong tag
#[session_test]
fn test_aes_gcm_wrong_tag_fails(session: HsmSession) {
    const IV_SIZE: usize = 12;

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesGcmKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let iv = [1u8; IV_SIZE];
    let plaintext = b"hello world".to_vec();

    // encrypt
    let mut enc = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), None).unwrap();

    let cipher_len = HsmEncrypter::encrypt(&mut enc, &key, &plaintext, None).unwrap();
    let mut ciphertext = vec![0u8; cipher_len];

    let written = HsmEncrypter::encrypt(&mut enc, &key, &plaintext, Some(&mut ciphertext)).unwrap();
    ciphertext.truncate(written);

    let mut tag = enc.tag().unwrap().to_vec();
    tag[0] ^= 0xFF; // corrupt tag

    // decrypt
    let mut dec = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag, None).unwrap();

    // size query (always succeeds)
    let plain_len = HsmDecrypter::decrypt(&mut dec, &key, &ciphertext, None).unwrap();

    // actual decrypt should fail
    let mut plaintext_out = vec![0u8; plain_len];

    let result = HsmDecrypter::decrypt(&mut dec, &key, &ciphertext, Some(&mut plaintext_out));

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-GCM key unwrap fails when unwrapping with mismatched bits in properties
#[session_test]
fn test_aes_gcm_unwrap_bits_mismatch_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let aes_key = vec![0x11u8; 32];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);

    let wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(128) // invalid
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}

/// verifies AES-GCM decryption fails when decrypting with wrong key
#[session_test]
fn test_aes_gcm_wrong_key_fails(session: HsmSession) {
    const IV_SIZE: usize = 12;

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    let key1 = HsmKeyManager::generate_key(&session, &mut algo, props.clone()).unwrap();
    let key2 = HsmKeyManager::generate_key(&session, &mut algo, props).unwrap();

    let iv = [1u8; IV_SIZE];
    let plaintext = b"hello world".to_vec();

    let mut enc = HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), None).unwrap();

    let len = HsmEncrypter::encrypt(&mut enc, &key1, &plaintext, None).unwrap();
    let mut ciphertext = vec![0u8; len];

    HsmEncrypter::encrypt(&mut enc, &key1, &plaintext, Some(&mut ciphertext)).unwrap();

    let tag = enc.tag().unwrap().to_vec();

    let mut dec = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag, None).unwrap();

    let plain_len = HsmDecrypter::decrypt(&mut dec, &key2, &ciphertext, None).unwrap();
    let mut plaintext_out = vec![0u8; plain_len];

    let result = HsmDecrypter::decrypt(&mut dec, &key2, &ciphertext, Some(&mut plaintext_out));

    assert!(result.is_err());

    HsmKeyManager::delete_key(key1).unwrap();
    HsmKeyManager::delete_key(key2).unwrap();
}

/// verifies AES-GCM key unmasking fails when unmasking with corrupted masked blob
#[session_test]
fn test_aes_gcm_unmask_corrupted_blob_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut gen_algo = HsmAesGcmKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(&session, &mut gen_algo, props).unwrap();

    let mut masked = key.masked_key_vec().unwrap();

    // corrupt masked blob
    masked[0] ^= 0xFF;

    let mut algo = HsmAesGcmKeyUnmaskAlgo::default();

    let result = HsmKeyManager::unmask_key(&session, &mut algo, &masked);

    assert!(result.is_err());

    HsmKeyManager::delete_key(key).unwrap();
}

/// verifies AES-GCM unwrap fails when wrapped blob is truncated
#[session_test]
fn test_aes_gcm_unwrap_truncated_blob_fails(session: HsmSession) {
    let (priv_key, pub_key) = get_rsa_unwrapping_key_pair(&session);

    let aes_key = vec![0x11u8; 32];

    let mut wrap_algo = HsmRsaAesWrapAlgo::new(HsmHashAlgo::Sha256, 32);

    let mut wrapped = HsmEncrypter::encrypt_vec(&mut wrap_algo, &pub_key, &aes_key).unwrap();

    wrapped.truncate(wrapped.len() - 8);

    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesGcm)
        .bits(256)
        .can_encrypt(true)
        .can_decrypt(true)
        .build()
        .unwrap();

    let mut unwrap_algo = HsmAesGcmKeyRsaAesKeyUnwrapAlgo::new(HsmHashAlgo::Sha256);

    let result = HsmKeyManager::unwrap_key(&mut unwrap_algo, &priv_key, &wrapped, props);

    assert!(result.is_err());
}
