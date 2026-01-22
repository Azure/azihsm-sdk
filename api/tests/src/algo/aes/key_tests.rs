// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

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
    const WRAP_BLOB_MAGIC: u64 = 0x5354_584D_5348_AA55;
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

#[session_test]
fn test_session_aes_128_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 128);
}

#[session_test]
fn test_session_aes_192_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 192);
}

#[session_test]
fn test_session_aes_256_key_generation(session: HsmSession) {
    test_session_aes_key_generation_common(&session, 256);
}

#[session_test]
fn test_aes_128_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 128, false);
}

#[session_test]
fn test_aes_192_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 192, false);
}

#[session_test]
fn test_aes_256_key_unwrap(session: HsmSession) {
    test_aes_key_unwrap_common(&session, 256, true);
}

#[session_test]
fn test_aes_128_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 128);
}

#[session_test]
fn test_aes_192_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 192);
}

#[session_test]
fn test_aes_256_key_unmask(session: HsmSession) {
    test_aes_key_unmask_common(&session, 256);
}

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

// Validate the unwrapped key is usable for AES-XTS encryption/decryption.

fn tweak_after_units(tweak: &[u8; 16], units: usize) -> [u8; 16] {
    u128::from_le_bytes(*tweak)
        .checked_add(units as u128)
        .expect("tweak increment overflow")
        .to_le_bytes()
}

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
