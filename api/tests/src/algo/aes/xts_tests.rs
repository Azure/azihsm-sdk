// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

const AES_XTS_TEST_KEY_BIT_SIZE: usize = 512;
const AES_XTS_TEST_TWEAK_SIZE: usize = 16; // 128 bits

fn tweak_after_units(tweak: &[u8; AES_XTS_TEST_TWEAK_SIZE], units: usize) -> Vec<u8> {
    let start = u128::from_le_bytes(*tweak);
    start
        .checked_add(units as u128)
        .expect("tweak increment overflow")
        .to_le_bytes()
        .to_vec()
}

fn xts_encrypt(
    key: &HsmAesXtsKey,
    tweak: &[u8; AES_XTS_TEST_TWEAK_SIZE],
    dul: usize,
    plaintext: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mut algo = HsmAesXtsAlgo::new(tweak, dul)?;

    // Size query should be stable and not mutate tweak.
    let out_len = algo.encrypt(key, plaintext, None)?;
    assert_eq!(algo.tweak(), tweak.to_vec());

    let mut out = vec![0u8; out_len];
    let written = algo.encrypt(key, plaintext, Some(&mut out))?;
    out.truncate(written);

    Ok((out, algo.tweak()))
}

fn xts_decrypt(
    key: &HsmAesXtsKey,
    tweak: &[u8; AES_XTS_TEST_TWEAK_SIZE],
    dul: usize,
    ciphertext: &[u8],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let mut algo = HsmAesXtsAlgo::new(tweak, dul)?;

    // Size query should be stable and not mutate tweak.
    let out_len = algo.decrypt(key, ciphertext, None)?;
    assert_eq!(algo.tweak(), tweak.to_vec());

    let mut out = vec![0u8; out_len];
    let written = algo.decrypt(key, ciphertext, Some(&mut out))?;
    out.truncate(written);

    Ok((out, algo.tweak()))
}

fn xts_encrypt_streaming(
    key: &HsmAesXtsKey,
    tweak: &[u8; AES_XTS_TEST_TWEAK_SIZE],
    dul: usize,
    plaintext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let enc_algo = HsmAesXtsAlgo::new(tweak, dul)?;
    let mut enc_ctx = enc_algo.encrypt_init(key.clone())?;

    let mut ciphertext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < plaintext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(plaintext.len() - offset);
        assert!(size.is_multiple_of(dul));
        let chunk = &plaintext[offset..offset + size];
        offset += size;
        i += 1;

        let out_len = enc_ctx.update(chunk, None)?;
        let mut out = vec![0u8; out_len];
        let written = enc_ctx.update(chunk, Some(&mut out))?;
        ciphertext.extend_from_slice(&out[..written]);
    }

    let out_len = enc_ctx.finish(None)?;
    let mut out = vec![0u8; out_len];
    let written = enc_ctx.finish(Some(out.as_mut()))?;
    ciphertext.extend_from_slice(&out[..written]);

    let algo = enc_ctx.into_algo();
    Ok((ciphertext, algo.tweak()))
}

fn xts_decrypt_streaming(
    key: &HsmAesXtsKey,
    tweak: &[u8; AES_XTS_TEST_TWEAK_SIZE],
    dul: usize,
    ciphertext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<(Vec<u8>, Vec<u8>)> {
    let dec_algo = HsmAesXtsAlgo::new(tweak, dul)?;
    let mut dec_ctx = dec_algo.decrypt_init(key.clone())?;

    let mut plaintext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < ciphertext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(ciphertext.len() - offset);
        assert!(size.is_multiple_of(dul));
        let chunk = &ciphertext[offset..offset + size];
        offset += size;
        i += 1;

        let out_len = dec_ctx.update(chunk, None)?;
        let mut out = vec![0u8; out_len];
        let written = dec_ctx.update(chunk, Some(&mut out))?;
        plaintext.extend_from_slice(&out[..written]);
    }

    let out_len = dec_ctx.finish(None)?;
    let mut out = vec![0u8; out_len];
    let written = dec_ctx.finish(Some(out.as_mut()))?;
    plaintext.extend_from_slice(&out[..written]);

    let algo = dec_ctx.into_algo();
    Ok((plaintext, algo.tweak()))
}

fn aes_xts_generate_key_with_caps(
    session: &HsmSession,
    can_encrypt: bool,
    can_decrypt: bool,
) -> HsmResult<HsmAesXtsKey> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(can_encrypt)
        .can_decrypt(can_decrypt)
        .is_session(true)
        .build()
        .expect("Failed to build key props");
    let mut algo = HsmAesXtsKeyGenAlgo::default();
    let key = HsmKeyManager::generate_key(session, &mut algo, props)
        .expect("Failed to generate AES XTS key");
    assert_eq!(key.class(), HsmKeyClass::Secret, "Key class mismatch");
    assert_eq!(key.kind(), HsmKeyKind::AesXts, "Key kind mismatch");
    assert_eq!(
        key.bits(),
        AES_XTS_TEST_KEY_BIT_SIZE as u32,
        "Key bits mismatch"
    );
    assert_eq!(
        key.can_encrypt(),
        can_encrypt,
        "Key can_encrypt property mismatch"
    );
    assert_eq!(
        key.can_decrypt(),
        can_decrypt,
        "Key can_decrypt property mismatch"
    );
    Ok(key)
}

fn aes_xts_generate_key(session: &HsmSession) -> HsmResult<HsmAesXtsKey> {
    aes_xts_generate_key_with_caps(session, true, true)
}

#[session_test]
fn aes_xts_encrypt_decrypt_test(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");

    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512; // Data Unit Length

    let plaintext: Vec<u8> = vec![0x11u8; 2048]; // 4 data units at DUL=512

    let (ciphertext, enc_tweak_after) =
        xts_encrypt(&key, &tweak, dul, &plaintext).expect("Encryption failed");
    assert_eq!(ciphertext.len(), plaintext.len(), "Encrypted size mismatch");
    assert_eq!(
        enc_tweak_after,
        tweak_after_units(&tweak, plaintext.len() / dul)
    );

    let (decrypted_text, dec_tweak_after) =
        xts_decrypt(&key, &tweak, dul, &ciphertext).expect("Decryption failed");
    assert_eq!(decrypted_text, plaintext);
    assert_eq!(
        dec_tweak_after,
        tweak_after_units(&tweak, plaintext.len() / dul)
    );
}

/// AES-XTS roundtrip with DUL=4096 and 2 data units.
#[session_test]
fn aes_xts_encrypt_decrypt_dul_4096_two_units(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 4096;

    let plaintext: Vec<u8> = vec![0xABu8; dul * 2];
    let (ciphertext, enc_tweak_after) =
        xts_encrypt(&key, &tweak, dul, &plaintext).expect("Encryption failed");
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_eq!(enc_tweak_after, tweak_after_units(&tweak, 2));

    let (decrypted, dec_tweak_after) =
        xts_decrypt(&key, &tweak, dul, &ciphertext).expect("Decryption failed");
    assert_eq!(decrypted, plaintext);
    assert_eq!(dec_tweak_after, tweak_after_units(&tweak, 2));
}

/// Streaming AES-XTS encrypt/decrypt should match single-shot output.
#[session_test]
fn aes_xts_streaming_matches_single_shot(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let plaintext: Vec<u8> = vec![0x5Au8; dul * 6];
    let chunk_sizes = [dul * 2, dul * 1, dul * 3];

    let (single_ct, _) = xts_encrypt(&key, &tweak, dul, &plaintext).expect("encrypt failed");
    let (stream_ct, stream_enc_tweak_after) =
        xts_encrypt_streaming(&key, &tweak, dul, &plaintext, &chunk_sizes)
            .expect("stream encrypt failed");

    assert_eq!(stream_ct, single_ct);
    assert_eq!(
        stream_enc_tweak_after,
        tweak_after_units(&tweak, plaintext.len() / dul)
    );

    let (single_pt, _) = xts_decrypt(&key, &tweak, dul, &single_ct).expect("decrypt failed");
    let (stream_pt, stream_dec_tweak_after) =
        xts_decrypt_streaming(&key, &tweak, dul, &stream_ct, &chunk_sizes)
            .expect("stream decrypt failed");

    assert_eq!(stream_pt, single_pt);
    assert_eq!(stream_pt, plaintext);
    assert_eq!(
        stream_dec_tweak_after,
        tweak_after_units(&tweak, plaintext.len() / dul)
    );
}

/// Streaming update should reject non-DUL-aligned chunks.
#[session_test]
fn aes_xts_streaming_rejects_partial_data_unit(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let enc_algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let mut enc_ctx = enc_algo
        .encrypt_init(key.clone())
        .expect("Failed to init streaming encrypt");

    let bad_chunk = [0x11u8; 1];
    let err = enc_ctx.update(&bad_chunk, None).unwrap_err();
    assert!(matches!(err, HsmError::InvalidArgument));
}

/// `HsmAesXtsAlgo::new` should reject tweak sizes other than 16 bytes.
#[test]
fn aes_xts_new_rejects_invalid_tweak_len() {
    let dul: usize = 512;

    let tweak_short = [0u8; AES_XTS_TEST_TWEAK_SIZE - 1];
    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak_short, dul),
        Err(HsmError::InvalidArgument)
    ));

    let tweak_long = [0u8; AES_XTS_TEST_TWEAK_SIZE + 1];
    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak_long, dul),
        Err(HsmError::InvalidArgument)
    ));
}

/// `HsmAesXtsAlgo::new` should reject unsupported DUL sizes.
#[test]
fn aes_xts_new_rejects_invalid_dul() {
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak, 511),
        Err(HsmError::InvalidArgument)
    ));

    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak, 1024),
        Err(HsmError::InvalidArgument)
    ));
}

/// Single-shot encrypt/decrypt should reject inputs that are not DUL-aligned.
#[session_test]
fn aes_xts_rejects_non_dul_aligned_input(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let plaintext = vec![0x11u8; dul + 1];
    let mut ciphertext = vec![0u8; plaintext.len()];
    let err = algo
        .encrypt(&key, &plaintext, Some(ciphertext.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidArgument));

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let ciphertext = vec![0x22u8; dul + 1];
    let mut out = vec![0u8; ciphertext.len()];
    let err = algo
        .decrypt(&key, &ciphertext, Some(out.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidArgument));
}

/// Encrypt/decrypt should return `BufferTooSmall` when output is too short.
#[session_test]
fn aes_xts_buffer_too_small(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let plaintext = vec![0x11u8; dul * 2];
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let mut too_small = vec![0u8; plaintext.len() - 1];
    let err = algo
        .encrypt(&key, &plaintext, Some(too_small.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::BufferTooSmall));

    let (ciphertext, _) = xts_encrypt(&key, &tweak, dul, &plaintext).expect("encrypt failed");
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let mut too_small = vec![0u8; ciphertext.len() - 1];
    let err = algo
        .decrypt(&key, &ciphertext, Some(too_small.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::BufferTooSmall));
}

/// Streaming update should return `BufferTooSmall` when output is too short.
#[session_test]
fn aes_xts_streaming_buffer_too_small(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let enc_algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let mut enc_ctx = enc_algo
        .encrypt_init(key.clone())
        .expect("Failed to init streaming encrypt");

    let chunk = vec![0x11u8; dul];
    let mut out = vec![0u8; dul - 1];
    let err = enc_ctx.update(&chunk, Some(out.as_mut())).unwrap_err();
    assert!(matches!(err, HsmError::BufferTooSmall));
}

/// Encrypt/decrypt should detect tweak overflow when actual output is requested.
#[session_test]
fn aes_xts_tweak_overflow_rejected(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");
    let dul: usize = 512;
    let tweak = u128::MAX.to_le_bytes();

    let plaintext = vec![0x11u8; dul];
    let mut out = vec![0u8; plaintext.len()];
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let err = algo
        .encrypt(&key, &plaintext, Some(out.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidTweak));

    let ciphertext = vec![0x22u8; dul];
    let mut out = vec![0u8; ciphertext.len()];
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let err = algo
        .decrypt(&key, &ciphertext, Some(out.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidTweak));
}

/// Encrypt should fail with `InvalidKey` when the key is not permitted to encrypt.
#[session_test]
fn aes_xts_encrypt_rejects_key_without_encrypt_cap(session: HsmSession) {
    let key =
        aes_xts_generate_key_with_caps(&session, false, true).expect("Failed to generate XTS key");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let plaintext = vec![0x11u8; dul];
    let mut out = vec![0u8; plaintext.len()];
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let err = algo
        .encrypt(&key, &plaintext, Some(out.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidKey));
}

/// Decrypt should fail with `InvalidKey` when the key is not permitted to decrypt.
#[session_test]
fn aes_xts_decrypt_rejects_key_without_decrypt_cap(session: HsmSession) {
    let key =
        aes_xts_generate_key_with_caps(&session, true, false).expect("Failed to generate XTS key");
    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512;

    let ciphertext = vec![0x22u8; dul];
    let mut out = vec![0u8; ciphertext.len()];
    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");
    let err = algo
        .decrypt(&key, &ciphertext, Some(out.as_mut()))
        .unwrap_err();
    assert!(matches!(err, HsmError::InvalidKey));
}
