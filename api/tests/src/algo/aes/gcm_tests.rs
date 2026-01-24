// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

const AES_GCM_IV_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;

/// Generate a session-only AES-GCM key.
fn aes_gcm_generate_key(session: &HsmSession) -> HsmAesGcmKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::AesGcm)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key properties");

    let mut algo = HsmAesGcmKeyGenAlgo::default();

    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES-GCM key")
}

/// Generate a non-session AES-GCM key for streaming tests.
fn aes_gcm_generate_streaming_key(session: &HsmSession) -> HsmAesGcmKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::AesGcm)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(false)
        .build()
        .expect("Failed to build key properties");

    let mut algo = HsmAesGcmKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES-GCM key")
}

fn verify_generated_aes_gcm_key_properties(key: &HsmAesGcmKey, is_session: bool) {
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::AesGcm, "Key kind mismatch");
    assert_eq!(key.bits(), 256, "Key bits mismatch");
    assert!(key.is_local(), "Key should be local");
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

/// Create an AES-GCM algorithm instance for encryption.
fn new_gcm_encrypt_algo(iv: &[u8], aad: Option<Vec<u8>>) -> HsmAesGcmAlgo {
    HsmAesGcmAlgo::new_for_encryption(iv.to_vec(), aad).expect("Failed to create AES GCM algo")
}

/// Create an AES-GCM algorithm instance for decryption.
fn new_gcm_decrypt_algo(iv: &[u8], tag: &[u8], aad: Option<Vec<u8>>) -> HsmAesGcmAlgo {
    HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), tag.to_vec(), aad)
        .expect("Failed to create AES GCM algo")
}

/// Encrypt data with AES-GCM.
fn gcm_encrypt(
    key: &HsmAesGcmKey,
    iv: &[u8],
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let cipher_len = {
        let mut algo = new_gcm_encrypt_algo(iv, aad.clone());
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut ciphertext = vec![0u8; cipher_len];

    let mut algo = new_gcm_encrypt_algo(iv, aad);
    let written = HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut ciphertext))?;
    ciphertext.truncate(written);

    let tag = algo.tag().ok_or(HsmError::InternalError)?.to_vec();

    Ok((ciphertext, tag))
}

/// Decrypt data with AES-GCM.
fn gcm_decrypt(
    key: &HsmAesGcmKey,
    iv: &[u8],
    tag: &[u8],
    aad: Option<Vec<u8>>,
    ciphertext: &[u8],
) -> HsmResult<Vec<u8>> {
    let plain_len = {
        let mut algo = new_gcm_decrypt_algo(iv, tag, aad.clone());
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut plaintext = vec![0u8; plain_len];

    let mut algo = new_gcm_decrypt_algo(iv, tag, aad);
    let written = HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut plaintext))?;
    plaintext.truncate(written);

    Ok(plaintext)
}

fn run_gcm_roundtrip(session: &HsmSession, iv: &[u8], aad: Option<Vec<u8>>, plaintext: &[u8]) {
    let key = aes_gcm_generate_key(session);

    let (ciphertext, tag) =
        gcm_encrypt(&key, iv, aad.clone(), plaintext).expect("Failed to encrypt");

    // GCM ciphertext is same length as plaintext
    assert_eq!(ciphertext.len(), plaintext.len());
    // Tag is always 16 bytes
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt(&key, iv, &tag, aad, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

// Key generation tests
#[session_test]
fn test_aes_gcm_key_gen_256_session(session: HsmSession) {
    let key = aes_gcm_generate_key(&session);
    verify_generated_aes_gcm_key_properties(&key, true);
}

#[session_test]
fn test_aes_gcm_key_gen_256_non_session(session: HsmSession) {
    let key = aes_gcm_generate_streaming_key(&session);
    verify_generated_aes_gcm_key_properties(&key, false);
}

// Basic encryption/decryption tests
#[session_test]
fn test_gcm_crypt_basic(session: HsmSession) {
    let iv = [0x00u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0x11u8; 16];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

#[session_test]
fn test_gcm_crypt_with_aad(session: HsmSession) {
    let iv = [0x10u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0x22u8; 32];
    let aad = Some(b"additional authenticated data".to_vec());
    run_gcm_roundtrip(&session, &iv, aad, &plaintext);
}

#[session_test]
fn test_gcm_crypt_large_data(session: HsmSession) {
    let iv = [0x20u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0xAAu8; 4096];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

#[session_test]
fn test_gcm_crypt_large_data_with_aad(session: HsmSession) {
    let iv = [0x30u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0xBBu8; 4096];
    let aad = Some(vec![0xCCu8; 256]);
    run_gcm_roundtrip(&session, &iv, aad, &plaintext);
}

#[session_test]
fn test_gcm_crypt_small_data(session: HsmSession) {
    let iv = [0x40u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0x55u8; 1];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

// Negative tests
#[session_test]
fn test_gcm_invalid_iv_fails(mut _session: HsmSession) {
    let iv_too_short = vec![0u8; AES_GCM_IV_SIZE - 1];
    let iv_too_long = vec![0u8; AES_GCM_IV_SIZE + 1];

    assert!(matches!(
        HsmAesGcmAlgo::new_for_encryption(iv_too_short, None),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        HsmAesGcmAlgo::new_for_encryption(iv_too_long, None),
        Err(HsmError::InvalidArgument)
    ));
}

#[session_test]
fn test_gcm_invalid_tag_fails(mut _session: HsmSession) {
    let iv = vec![0u8; AES_GCM_IV_SIZE];
    let tag_too_short = vec![0u8; AES_GCM_TAG_SIZE - 1];
    let tag_too_long = vec![0u8; AES_GCM_TAG_SIZE + 1];

    assert!(matches!(
        HsmAesGcmAlgo::new_for_decryption(iv.clone(), tag_too_short, None),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        HsmAesGcmAlgo::new_for_decryption(iv, tag_too_long, None),
        Err(HsmError::InvalidArgument)
    ));
}

// Streaming tests
fn gcm_encrypt_streaming(
    key: &HsmAesGcmKey,
    iv: &[u8],
    aad: Option<Vec<u8>>,
    plaintext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let enc_algo = new_gcm_encrypt_algo(iv, aad);
    let mut enc_ctx = enc_algo.encrypt_init(key.clone())?;

    let mut ciphertext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < plaintext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(plaintext.len() - offset);
        let chunk = &plaintext[offset..offset + size];
        offset += size;
        i += 1;

        let out = enc_ctx.update_vec(chunk)?;
        ciphertext.extend_from_slice(&out);
    }

    let out = enc_ctx.finish_vec()?;
    ciphertext.extend_from_slice(&out);

    let tag = enc_ctx
        .algo()
        .tag()
        .ok_or(HsmError::InternalError)?
        .to_vec();

    Ok((ciphertext, tag))
}

fn gcm_decrypt_streaming(
    key: &HsmAesGcmKey,
    iv: &[u8],
    tag: &[u8],
    aad: Option<Vec<u8>>,
    ciphertext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<Vec<u8>> {
    let dec_algo = new_gcm_decrypt_algo(iv, tag, aad);
    let mut dec_ctx = dec_algo.decrypt_init(key.clone())?;

    let mut plaintext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < ciphertext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(ciphertext.len() - offset);
        let chunk = &ciphertext[offset..offset + size];
        offset += size;
        i += 1;

        let out = dec_ctx.update_vec(chunk)?;
        plaintext.extend_from_slice(&out);
    }

    let out = dec_ctx.finish_vec()?;
    plaintext.extend_from_slice(&out);

    Ok(plaintext)
}

#[session_test]
fn test_gcm_streaming_encrypt(session: HsmSession) {
    let iv = [0xAAu8; AES_GCM_IV_SIZE];
    let plaintext = vec![0xBBu8; 2048];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[512]).expect("Failed to encrypt");

    assert_eq!(ciphertext.len(), plaintext.len());
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    // Decrypt with single-shot to verify
    let decrypted = gcm_decrypt(&key, &iv, &tag, None, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

#[session_test]
fn test_gcm_streaming_decrypt(session: HsmSession) {
    let iv = [0xCCu8; AES_GCM_IV_SIZE];
    let plaintext = vec![0xDDu8; 2048];

    let key = aes_gcm_generate_streaming_key(&session);

    // Encrypt with single-shot
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).expect("Failed to encrypt");

    // Decrypt with streaming
    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[512])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

#[session_test]
fn test_gcm_streaming_roundtrip(session: HsmSession) {
    let iv = [0xEEu8; AES_GCM_IV_SIZE];
    let plaintext = vec![0xFFu8; 3000];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[333, 777]).expect("Failed to encrypt");

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[500, 100])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

#[session_test]
fn test_gcm_streaming_with_aad(session: HsmSession) {
    let iv = [0x11u8; AES_GCM_IV_SIZE];
    let plaintext = vec![0x22u8; 1500];
    let aad = Some(b"streaming aad test".to_vec());

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, aad.clone(), &plaintext, &[200])
        .expect("Failed to encrypt");

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, aad, &ciphertext, &[300])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}
