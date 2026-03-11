// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::Rng;

use super::*;

const AES_GCM_IV_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const AES_GCM_MAX_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB, arbitrary limit for testing

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

    // For GCM, update() only buffers data and returns 0
    // All encryption happens in finish()
    let mut offset = 0;
    let mut i = 0;
    while offset < plaintext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(plaintext.len() - offset);
        let chunk = &plaintext[offset..offset + size];
        offset += size;
        i += 1;

        // update() buffers data, returns 0
        let bytes = enc_ctx.update_vec(chunk)?;
        assert_eq!(bytes.len(), 0, "GCM update() should return empty output");
    }

    // finish() performs the actual encryption and returns all ciphertext
    let ciphertext = enc_ctx.finish_vec()?;

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

    // For GCM, update() only buffers data and returns 0
    // All decryption happens in finish()
    let mut offset = 0;
    let mut i = 0;
    while offset < ciphertext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(ciphertext.len() - offset);
        let chunk = &ciphertext[offset..offset + size];

        offset += size;
        i += 1;

        // update() buffers data, returns 0
        let bytes = dec_ctx.update_vec(chunk)?;
        assert_eq!(bytes.len(), 0, "GCM update() should return empty output");
    }

    // finish() performs the actual decryption and returns all plaintext
    let plaintext = dec_ctx.finish_vec()?;

    Ok(plaintext)
}

fn test_iv() -> [u8; AES_GCM_IV_SIZE] {
    Rng::rand_vec(AES_GCM_IV_SIZE)
        .expect("RNG failure generating IV")
        .try_into()
        .expect("IV length mismatch")
}

// Key generation tests

/// Verify AES-GCM session key generation produces a valid 256-bit key with expected properties.
#[session_test]
fn test_aes_gcm_key_gen_256_session(session: HsmSession) {
    let key = aes_gcm_generate_key(&session);
    verify_generated_aes_gcm_key_properties(&key, true);
}

/// Verify AES-GCM non-session key generation produces a valid 256-bit persistent key.
#[session_test]
fn test_aes_gcm_key_gen_256_non_session(session: HsmSession) {
    let key = aes_gcm_generate_streaming_key(&session);
    verify_generated_aes_gcm_key_properties(&key, false);
}

///Verify AES-GCM encrypt/decrypt roundtrip for a basic single block message.
#[session_test]
fn test_gcm_crypt_basic(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x11u8; 16];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

/// Verify AES-GCM encrypt/decrypt roundtrip when Additional Authenticated Data (AAD) is present.
#[session_test]
fn test_gcm_crypt_with_aad(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; 32];
    let aad = Some(b"additional authenticated data".to_vec());
    run_gcm_roundtrip(&session, &iv, aad, &plaintext);
}

/// Verify AES-GCM encryption/decryption works for moderately large plaintext.
#[session_test]
fn test_gcm_crypt_large_data(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xAAu8; 4096];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

/// Verify AES-GCM encryption/decryption works for large plaintext with AAD.
#[session_test]
fn test_gcm_crypt_large_data_with_aad(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xBBu8; 4096];
    let aad = Some(vec![0xCCu8; 256]);
    run_gcm_roundtrip(&session, &iv, aad, &plaintext);
}

// Verify AES-GCM encrypt/decrypt roundtrip for minimal (1-byte) plaintext.
#[session_test]
fn test_gcm_crypt_small_data(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x55u8; 1];
    run_gcm_roundtrip(&session, &iv, None, &plaintext);
}

// Negative tests

/// Ensure AES-GCM encryption initialization fails when IV size is invalid.
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

/// Ensure AES-GCM decryption initialization fails when authentication tag size is invalid.
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

/// Verify streaming AES-GCM encryption produces valid ciphertext and tag.
#[session_test]
fn test_gcm_streaming_encrypt(session: HsmSession) {
    let iv = test_iv();
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

/// Verify streaming AES-GCM decryption correctly recovers plaintext.
#[session_test]
fn test_gcm_streaming_decrypt(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xDDu8; 2048];

    let key = aes_gcm_generate_streaming_key(&session);

    // Encrypt with single-shot
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).expect("Failed to encrypt");

    // Decrypt with streaming
    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[512])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify full streaming AES-GCM roundtrip using irregular chunk sizes.
#[session_test]
fn test_gcm_streaming_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xFFu8; 3000];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[333, 777]).expect("Failed to encrypt");

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[500, 100])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify streaming AES-GCM encryption/decryption works correctly when AAD is provided.
#[session_test]
fn test_gcm_streaming_with_aad(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; 1500];
    let aad = Some(b"streaming aad test".to_vec());

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, aad.clone(), &plaintext, &[200])
        .expect("Failed to encrypt");

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, aad, &ciphertext, &[300])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify streaming AES-GCM correctly handles empty plaintext input.
#[session_test]
fn test_gcm_streaming_empty_plaintext_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[64]).expect("Failed to encrypt");
    assert_eq!(ciphertext.len(), 0);
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[64])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Ensure streaming AES-GCM decryption fails when authentication tag is corrupted.
#[session_test]
fn test_gcm_streaming_wrong_tag_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x55u8; 1024];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, mut tag) =
        gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[128]).expect("Failed to encrypt");
    tag[0] ^= 0xFF;

    let result = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[128]);
    assert!(
        result.is_err(),
        "Streaming decryption should fail with wrong tag"
    );
}

/// Verify streaming AES-GCM decryption works correctly for larger (8KB) ciphertext.
#[session_test]
fn test_gcm_streaming_decrypt_8k(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x99u8; 8192]; // 8KB plaintext

    let key = aes_gcm_generate_streaming_key(&session);

    // Encrypt with single-shot
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).expect("Failed to encrypt");

    // Decrypt with streaming using 512-byte chunks
    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[512])
        .expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify AES-GCM correctly handles roundtrip encryption/decryption of an empty plaintext.
#[session_test]
fn test_gcm_empty_plaintext_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];

    let key = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).expect("Failed to encrypt");
    assert_eq!(ciphertext.len(), 0);
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt(&key, &iv, &tag, None, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Verify AES-GCM decrypt fails when authentication tag is modified.
#[session_test]
fn test_gcm_wrong_tag_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x77u8; 128];

    let key = aes_gcm_generate_key(&session);

    let (ciphertext, mut tag) =
        gcm_encrypt(&key, &iv, None, &plaintext).expect("Failed to encrypt");
    tag[0] ^= 0xFF;

    let result = gcm_decrypt(&key, &iv, &tag, None, &ciphertext);
    assert!(result.is_err(), "Decryption should fail with wrong tag");
}

/// Verify AES-GCM decrypt fails when incorrect AAD is supplied.
#[session_test]
fn test_gcm_wrong_aad_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x88u8; 256];
    let aad = Some(b"aad-value".to_vec());
    let wrong_aad = Some(b"aad-wrong".to_vec());

    let key = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, aad, &plaintext).expect("Failed to encrypt");

    let result = gcm_decrypt(&key, &iv, &tag, wrong_aad, &ciphertext);
    assert!(result.is_err(), "Decryption should fail with wrong AAD");
}

/// Verify AES-GCM authentication detects tampered ciphertext.
#[session_test]
fn test_gcm_tampered_ciphertext_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xABu8; 256];
    let aad = Some(b"aad".to_vec());

    let key = aes_gcm_generate_key(&session);
    let (mut ciphertext, tag) = gcm_encrypt(&key, &iv, aad.clone(), &plaintext).unwrap();

    // Tamper ciphertext
    ciphertext[0] ^= 0x01;

    let res = gcm_decrypt(&key, &iv, &tag, aad, &ciphertext);
    assert!(res.is_err(), "Tampered ciphertext must fail authentication");
}

/// Verify AES-GCM decrypt fails when IV used during decryption differs from encryption.
#[session_test]
fn test_gcm_wrong_iv_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCDu8; 128];

    let key = aes_gcm_generate_key(&session);
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    let mut wrong_iv = iv;
    wrong_iv[0] = wrong_iv[0].wrapping_add(1);
    let res = gcm_decrypt(&key, &wrong_iv, &tag, None, &ciphertext);
    assert!(res.is_err(), "Wrong IV must fail authentication");
}

/// Verify AES-GCM decrypt fails when using a different key.
#[session_test]
fn test_gcm_wrong_key_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xEEu8; 64];

    let key1 = aes_gcm_generate_key(&session);
    let key2 = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key1, &iv, None, &plaintext).unwrap();
    let res = gcm_decrypt(&key2, &iv, &tag, None, &ciphertext);

    assert!(res.is_err(), "Decrypt with wrong key must fail");
}

/// Verify AES-GCM authentication fails when ciphertext is truncated.
#[session_test]
fn test_gcm_truncated_ciphertext_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x11u8; 128];

    let key = aes_gcm_generate_key(&session);
    let (mut ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    ciphertext.truncate(ciphertext.len() - 1);

    let res = gcm_decrypt(&key, &iv, &tag, None, &ciphertext);
    assert!(res.is_err(), "Truncated ciphertext must fail");
}

/// Ensure decrypt algorithm creation fails when authentication tag is missing.
#[session_test]
fn test_gcm_missing_tag_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; 64];

    let key = aes_gcm_generate_key(&session);
    let (_ciphertext, _tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    let empty_tag: Vec<u8> = vec![];

    let res = HsmAesGcmAlgo::new_for_decryption(iv.to_vec(), empty_tag, None);
    assert!(
        matches!(res, Err(HsmError::InvalidArgument)),
        "Creating decrypt algo with missing tag must fail"
    );
}

/// Verify AES-GCM decrypt fails when expected AAD is omitted.
#[session_test]
fn test_gcm_missing_aad_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x33u8; 128];
    let aad = Some(b"expected aad".to_vec());

    let key = aes_gcm_generate_key(&session);
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, aad, &plaintext).unwrap();

    let res = gcm_decrypt(&key, &iv, &tag, None, &ciphertext);
    assert!(res.is_err(), "Missing AAD must fail authentication");
}

/// Verify AES-GCM decrypt fails when unexpected AAD is supplied.
#[session_test]
fn test_gcm_unexpected_aad_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x44u8; 128];

    let key = aes_gcm_generate_key(&session);
    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    let unexpected_aad = Some(b"unexpected aad".to_vec());

    let res = gcm_decrypt(&key, &iv, &tag, unexpected_aad, &ciphertext);
    assert!(res.is_err(), "Unexpected AAD must fail authentication");
}

/// Verify AES-GCM encryption is deterministic when key, IV, plaintext, and AAD are identical.
#[session_test]
fn test_gcm_same_inputs_same_ciphertext_and_tag(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x55u8; 128];
    let aad = Some(b"aad".to_vec());

    let key = aes_gcm_generate_key(&session);

    let (ct1, tag1) = gcm_encrypt(&key, &iv, aad.clone(), &plaintext).unwrap();
    let (ct2, tag2) = gcm_encrypt(&key, &iv, aad, &plaintext).unwrap();

    assert_eq!(ct1, ct2, "Ciphertext must be deterministic for same inputs");
    assert_eq!(tag1, tag2, "Tag must be deterministic for same inputs");
}

/// Verify AES-GCM produces different ciphertext when IV changes
#[session_test]
fn test_gcm_different_ivs_produce_different_ciphertext(session: HsmSession) {
    let iv1 = test_iv();
    let mut iv2 = iv1;
    iv2[0] = iv2[0].wrapping_add(1);

    let plaintext = vec![0x66u8; 128];
    let key = aes_gcm_generate_key(&session);

    let (ct1, _) = gcm_encrypt(&key, &iv1, None, &plaintext).unwrap();
    let (ct2, _) = gcm_encrypt(&key, &iv2, None, &plaintext).unwrap();

    assert_ne!(
        ct1, ct2,
        "Different IVs should produce different ciphertext"
    );
}

/// Verify AES-GCM tag changes when AAD changes while plaintext and IV remain the same.
#[session_test]
fn test_gcm_same_plaintext_iv_different_aad_changes_tag(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x77u8; 128];
    let key = aes_gcm_generate_key(&session);

    let (ct1, tag1) = gcm_encrypt(&key, &iv, Some(b"aad1".to_vec()), &plaintext).unwrap();
    let (ct2, tag2) = gcm_encrypt(&key, &iv, Some(b"aad2".to_vec()), &plaintext).unwrap();

    assert_eq!(ct1, ct2, "Ciphertext should match for same PT/IV");
    assert_ne!(tag1, tag2, "Tags must differ for different AAD");
}

/// Verify AES-GCM single-shot encryption works across a range of plaintext sizes.
#[session_test]
fn test_gcm_single_shot_size_sweep(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_key(&session);

    for size in [0usize, 1, 15, 16, 31, 32, 127, 128, 1024, 4096] {
        let plaintext = vec![0xA5u8; size];
        let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();
        let decrypted = gcm_decrypt(&key, &iv, &tag, None, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "Roundtrip failed for size {}", size);
    }
}

/// Verify streaming AES-GCM works across varying plaintext sizes and chunk patterns.
#[session_test]
fn test_gcm_streaming_size_and_chunk_sweep(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_streaming_key(&session);

    for &size in &[0usize, 1, 31, 32, 127, 128, 1024] {
        let plaintext = vec![0x5Au8; size];

        for chunk_sizes in [&[1usize][..], &[7, 13, 64][..], &[256][..]] {
            let (ciphertext, tag) =
                gcm_encrypt_streaming(&key, &iv, None, &plaintext, chunk_sizes).unwrap();
            let decrypted =
                gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, chunk_sizes).unwrap();

            assert_eq!(
                decrypted, plaintext,
                "Streaming roundtrip failed (size={}, chunks={:?})",
                size, chunk_sizes
            );
        }
    }
}

/// Ensure streaming AES-GCM produces identical output to single-shot encryption.
#[session_test]
fn test_gcm_streaming_matches_single_shot(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x99u8; 2048];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ct1, tag1) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();
    let (ct2, tag2) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[7, 64, 13]).unwrap();

    assert_eq!(ct1, ct2, "Streaming ciphertext must match single-shot");
    assert_eq!(tag1, tag2, "Streaming tag must match single-shot");
}

/// Verify finish() drains the internal buffer and subsequent finish() returns no output.
#[session_test]
fn test_gcm_streaming_finish_drains_buffer(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x11u8; 128];

    let key = aes_gcm_generate_streaming_key(&session);
    let enc_algo = new_gcm_encrypt_algo(&iv, None);
    let mut ctx = enc_algo.encrypt_init(key).unwrap();

    let _ = ctx.update_vec(&plaintext).unwrap();

    let ct1 = ctx.finish_vec().unwrap();
    let ct2 = ctx.finish_vec().unwrap();

    assert!(!ct1.is_empty(), "First finish() should return ciphertext");
    assert!(ct2.is_empty(), "Second finish() should return empty output");
}

/// Verify update() after finish() performs no operation.
#[session_test]
fn test_gcm_streaming_update_after_finish_is_noop(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; 64];

    let key = aes_gcm_generate_streaming_key(&session);
    let enc_algo = new_gcm_encrypt_algo(&iv, None);
    let mut ctx = enc_algo.encrypt_init(key).unwrap();

    let _ = ctx.finish_vec().unwrap();

    let bytes = ctx.update_vec(&plaintext).unwrap();
    assert!(
        bytes.is_empty(),
        "update() after finish() should be a no-op for GCM"
    );
}

// =======================
// Additional coverage tests for AES-GCM
// =======================

/// Ensure encryption fails when output buffer is smaller than required ciphertext size.
#[session_test]
fn test_gcm_encrypt_buffer_too_small_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xB2u8; 64];
    let key = aes_gcm_generate_key(&session);

    let mut algo = new_gcm_encrypt_algo(&iv, None);

    let required = HsmEncrypter::encrypt(&mut algo, &key, &plaintext, None).unwrap();
    let mut small_buf = vec![0u8; required - 1];

    let res = HsmEncrypter::encrypt(&mut algo, &key, &plaintext, Some(&mut small_buf));
    assert!(matches!(res, Err(HsmError::BufferTooSmall)));
}

/// Ensure decryption fails when output buffer is smaller than required plaintext size.
#[session_test]
fn test_gcm_decrypt_buffer_too_small_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xC3u8; 64];
    let key = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    let mut algo = new_gcm_decrypt_algo(&iv, &tag, None);

    let required = HsmDecrypter::decrypt(&mut algo, &key, &ciphertext, None).unwrap();
    let mut small_buf = vec![0u8; required - 1];

    let res = HsmDecrypter::decrypt(&mut algo, &key, &ciphertext, Some(&mut small_buf));
    assert!(matches!(res, Err(HsmError::BufferTooSmall)));
}

/// Verify that performing a new encryption overwrites the previously generated authentication tag.
#[session_test]
fn test_gcm_encrypt_overwrites_previous_tag(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_key(&session);

    let mut algo = new_gcm_encrypt_algo(&iv, None);

    let pt1 = vec![0x11u8; 32];
    let pt2 = vec![0x22u8; 64];

    let _ = HsmEncrypter::encrypt(&mut algo, &key, &pt1, None).unwrap();
    let mut buf1 = vec![0u8; pt1.len()];
    let _ = HsmEncrypter::encrypt(&mut algo, &key, &pt1, Some(&mut buf1)).unwrap();
    let tag1 = algo.tag().unwrap().to_vec();

    let _ = HsmEncrypter::encrypt(&mut algo, &key, &pt2, None).unwrap();
    let mut buf2 = vec![0u8; pt2.len()];
    let _ = HsmEncrypter::encrypt(&mut algo, &key, &pt2, Some(&mut buf2)).unwrap();
    let tag2 = algo.tag().unwrap().to_vec();

    assert_ne!(
        tag1, tag2,
        "Tag should be overwritten after subsequent encryption"
    );
}

/// Ensure streaming update fails when buffered plaintext exceeds configured maximum.
#[session_test]
fn test_gcm_streaming_exceeds_max_buffer_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_streaming_key(&session);

    let enc_algo = new_gcm_encrypt_algo(&iv, None);
    let mut ctx = enc_algo.encrypt_init(key).unwrap();

    // Fill buffer to max
    let chunk = vec![0u8; AES_GCM_MAX_BUFFER_SIZE];
    ctx.update_vec(&chunk).unwrap();

    // Overflow by 1 byte
    let res = ctx.update_vec(&[0x01]);

    assert!(
        matches!(res, Err(HsmError::InvalidArgument)),
        "Exceeding max streaming buffer must fail"
    );
}

/// Verify update(None) returns zero output size for streaming GCM mode.
#[session_test]
fn test_gcm_streaming_update_size_query_returns_zero(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_streaming_key(&session);

    let enc_algo = new_gcm_encrypt_algo(&iv, None);
    let mut ctx = enc_algo.encrypt_init(key).unwrap();

    let pt = vec![0x44u8; 128];

    let size = ctx.update(&pt, None).unwrap();
    assert_eq!(size, 0, "GCM streaming update(None) must return 0");
}

/// Verify finish(None) reports correct ciphertext size without writing output.
#[session_test]
fn test_gcm_streaming_finish_size_query(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x55u8; 256];
    let key = aes_gcm_generate_streaming_key(&session);

    let enc_algo = new_gcm_encrypt_algo(&iv, None);
    let mut ctx = enc_algo.encrypt_init(key).unwrap();

    let _ = ctx.update_vec(&plaintext).unwrap();

    let size = ctx.finish(None).unwrap();
    assert_eq!(
        size,
        plaintext.len(),
        "finish(None) must return total ciphertext size"
    );
}

/// Verify streaming AES-GCM decryption fails when the output buffer is smaller than required plaintext size.
#[session_test]
fn test_gcm_streaming_decrypt_buffer_too_small_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x66u8; 128];
    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, None, &plaintext).unwrap();

    let dec_algo = new_gcm_decrypt_algo(&iv, &tag, None);
    let mut ctx = dec_algo.decrypt_init(key).unwrap();

    let _ = ctx.update_vec(&ciphertext).unwrap();

    let mut small_buf = vec![0u8; plaintext.len() - 1];
    let res = ctx.finish(Some(&mut small_buf));

    assert!(matches!(res, Err(HsmError::BufferTooSmall)));
}

/// Verify AES-GCM supports authenticating AAD-only messages (empty plaintext).
#[session_test]
fn test_gcm_aad_only_message_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];
    let aad = Some(b"aad-only-message".to_vec());

    let key = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, aad.clone(), &plaintext).unwrap();
    assert!(ciphertext.is_empty());
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt(&key, &iv, &tag, aad, &ciphertext).unwrap();
    assert!(decrypted.is_empty());
}

/// Ensure streaming AES-GCM decrypt initialization fails when no authentication tag is provided.
#[session_test]
fn test_gcm_streaming_decrypt_init_without_tag_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_streaming_key(&session);

    let algo = new_gcm_encrypt_algo(&iv, None);
    let res = algo.decrypt_init(key);

    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// Verify streaming AES-GCM decryption fails when using a different key than encryption.
#[session_test]
fn test_gcm_streaming_wrong_key_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xAAu8; 256];

    let key1 = aes_gcm_generate_streaming_key(&session);
    let key2 = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) = gcm_encrypt_streaming(&key1, &iv, None, &plaintext, &[64]).unwrap();

    let res = gcm_decrypt_streaming(&key2, &iv, &tag, None, &ciphertext, &[64]);

    assert!(res.is_err(), "Streaming decrypt with wrong key must fail");
}

/// Verify streaming AES-GCM decryption fails when the IV differs from the encryption IV.
#[session_test]
fn test_gcm_streaming_wrong_iv_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xBBu8; 256];

    let key = aes_gcm_generate_streaming_key(&session);
    let (ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[64]).unwrap();

    let mut wrong_iv = iv;
    wrong_iv[0] = wrong_iv[0].wrapping_add(1);

    let res = gcm_decrypt_streaming(&key, &wrong_iv, &tag, None, &ciphertext, &[64]);

    assert!(res.is_err(), "Streaming decrypt with wrong IV must fail");
}

/// Verify streaming AES-GCM authentication detects tampered ciphertext.
#[session_test]
fn test_gcm_streaming_tampered_ciphertext_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCCu8; 256];

    let key = aes_gcm_generate_streaming_key(&session);
    let (mut ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[32]).unwrap();

    ciphertext[0] ^= 0x01;

    let res = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[32]);

    assert!(res.is_err(), "Streaming tampered ciphertext must fail");
}

/// Ensure AES-GCM decryption fails when the algorithm instance does not contain an authentication tag.
#[session_test]
fn test_gcm_decrypt_without_tag_in_algo_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xDDu8; 64];
    let key = aes_gcm_generate_key(&session);

    let mut algo = new_gcm_encrypt_algo(&iv, None); // encryption algo has no tag

    let mut out = vec![0u8; plaintext.len()];
    let res = HsmDecrypter::decrypt(&mut algo, &key, &plaintext, Some(&mut out));

    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// Verify streaming AES-GCM decrypt context allows finish() only once and rejects subsequent calls.
#[session_test]
fn test_gcm_streaming_decrypt_finish_is_single_use(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xEEu8; 128];

    let key = aes_gcm_generate_streaming_key(&session);
    let (ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[64]).unwrap();

    let dec_algo = new_gcm_decrypt_algo(&iv, &tag, None);
    let mut ctx = dec_algo.decrypt_init(key).unwrap();

    ctx.update_vec(&ciphertext).unwrap();

    let pt1 = ctx.finish_vec().unwrap();
    assert_eq!(pt1, plaintext);

    // Second finish should fail (context is effectively consumed)
    let res = ctx.finish_vec();
    assert!(
        res.is_err(),
        "Streaming decrypt context should not allow finish() twice"
    );
}

/// Verify streaming AES-GCM correctly authenticates AAD-only messages with empty plaintext.
#[session_test]
fn test_gcm_streaming_aad_only_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];
    let aad = Some(b"streaming aad".to_vec());

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, aad.clone(), &plaintext, &[16]).unwrap();

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, aad, &ciphertext, &[16]).unwrap();

    assert!(decrypted.is_empty());
}

/// Verify streaming AES-GCM encryption is deterministic for identical inputs regardless of chunk sizes.
#[session_test]
fn test_gcm_streaming_same_inputs_deterministic(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x99u8; 512];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ct1, tag1) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[17, 31]).unwrap();
    let (ct2, tag2) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[64]).unwrap();

    assert_eq!(ct1, ct2);
    assert_eq!(tag1, tag2);
}

// ========================================================
// 🔒 Additional High-Value AES-GCM Coverage Tests
// ========================================================

/// Verify streaming AES-GCM decryption fails when incorrect AAD is supplied.
#[session_test]
fn test_gcm_streaming_wrong_aad_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; 256];

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, Some(b"aad1".to_vec()), &plaintext, &[64]).unwrap();

    let res = gcm_decrypt_streaming(&key, &iv, &tag, Some(b"aad2".to_vec()), &ciphertext, &[64]);

    assert!(res.is_err(), "Streaming decrypt must fail with wrong AAD");
}

/// Verify streaming AES-GCM authentication fails when ciphertext is truncated.
#[session_test]
fn test_gcm_streaming_truncated_ciphertext_fails(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x33u8; 256];

    let key = aes_gcm_generate_streaming_key(&session);

    let (mut ciphertext, tag) = gcm_encrypt_streaming(&key, &iv, None, &plaintext, &[64]).unwrap();

    ciphertext.truncate(ciphertext.len() - 1);

    let res = gcm_decrypt_streaming(&key, &iv, &tag, None, &ciphertext, &[64]);

    assert!(res.is_err(), "Streaming truncated ciphertext must fail");
}

/// Ensure single-shot AES-GCM decryption fails when the algorithm instance does not contain a tag.
#[session_test]
fn test_gcm_single_shot_decrypt_without_tag_in_algo_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_gcm_generate_key(&session);

    let mut algo = new_gcm_encrypt_algo(&iv, None); // no tag set

    let mut out = vec![0u8; 16];
    let res = HsmDecrypter::decrypt(&mut algo, &key, &[0u8; 16], Some(&mut out));

    assert!(matches!(res, Err(HsmError::InvalidArgument)));
}

/// Ensure AES-GCM key generation fails if encrypt capability is disabled.
#[session_test]
fn test_gcm_generate_key_with_invalid_encrypt_capability_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::AesGcm)
        .can_encrypt(false)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo_gen = HsmAesGcmKeyGenAlgo::default();

    let res = HsmKeyManager::generate_key(&session, &mut algo_gen, props);

    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Ensure AES-GCM key generation fails if decrypt capability is disabled.
#[session_test]
fn test_gcm_generate_key_with_invalid_decrypt_capability_fails(session: HsmSession) {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(256)
        .key_kind(HsmKeyKind::AesGcm)
        .can_encrypt(true)
        .can_decrypt(false)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo_gen = HsmAesGcmKeyGenAlgo::default();

    let res = HsmKeyManager::generate_key(&session, &mut algo_gen, props);

    assert!(matches!(res, Err(HsmError::InvalidKeyProps)));
}

/// Verify AES-GCM roundtrip works when AAD is explicitly empty.
#[session_test]
fn test_gcm_empty_aad_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x11u8; 64];
    let aad = Some(vec![]);

    run_gcm_roundtrip(&session, &iv, aad, &plaintext);
}

/// Verify AES-GCM supports empty plaintext with explicitly empty AAD.
#[session_test]
fn test_gcm_empty_aad_and_empty_plaintext(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];
    let aad = Some(vec![]);

    let key = aes_gcm_generate_key(&session);

    let (ciphertext, tag) = gcm_encrypt(&key, &iv, aad.clone(), &plaintext).unwrap();

    assert!(ciphertext.is_empty());
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt(&key, &iv, &tag, aad, &ciphertext).unwrap();
    assert!(decrypted.is_empty());
}

/// Verify streaming AES-GCM works when AAD is explicitly empty.
#[session_test]
fn test_gcm_streaming_empty_aad_roundtrip(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x77u8; 128];
    let aad = Some(vec![]);

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, aad.clone(), &plaintext, &[32]).unwrap();

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, aad, &ciphertext, &[32]).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Verify streaming AES-GCM supports empty plaintext with explicitly empty AAD.
#[session_test]
fn test_gcm_streaming_empty_aad_and_empty_plaintext(session: HsmSession) {
    let iv = test_iv();
    let plaintext: Vec<u8> = vec![];
    let aad = Some(vec![]);

    let key = aes_gcm_generate_streaming_key(&session);

    let (ciphertext, tag) =
        gcm_encrypt_streaming(&key, &iv, aad.clone(), &plaintext, &[16]).unwrap();

    assert!(ciphertext.is_empty());
    assert_eq!(tag.len(), AES_GCM_TAG_SIZE);

    let decrypted = gcm_decrypt_streaming(&key, &iv, &tag, aad, &ciphertext, &[16]).unwrap();

    assert!(decrypted.is_empty());
}
