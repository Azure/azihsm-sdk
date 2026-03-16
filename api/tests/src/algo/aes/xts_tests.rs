// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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

/// AES-XTS roundtrip with DUL=16 (one AES block).
#[session_test]
fn aes_xts_encrypt_decrypt_dul_16(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");

    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 16;

    // 8 data units at DUL=16
    let plaintext: Vec<u8> = (0u8..128u8).collect();

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
    let chunk_sizes = [dul * 2, dul, dul * 3];

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
        HsmAesXtsAlgo::new(&tweak, 0),
        Err(HsmError::InvalidArgument)
    ));

    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak, 15),
        Err(HsmError::InvalidArgument)
    ));

    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak, 511),
        Err(HsmError::InvalidArgument)
    ));

    assert!(matches!(
        HsmAesXtsAlgo::new(&tweak, 8208),
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
/// Sweep representative valid DUL values and 1–2 units each.
#[session_test]
fn aes_xts_single_shot_dul_sweep(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    let duls = [16usize, 32, 64, 128, 256, 512, 1024, 4096, 8192];

    for dul in duls {
        for units in [1usize, 2usize] {
            let plaintext = vec![0x5Au8; dul * units];

            let (ct, _) = xts_encrypt(&key, &tweak, dul, &plaintext).unwrap();
            assert_eq!(ct.len(), plaintext.len());

            let (pt, _) = xts_decrypt(&key, &tweak, dul, &ct).unwrap();
            assert_eq!(pt, plaintext);
        }
    }
}

/// verifies AES-XTS streaming works correctly for large multi-chunk inputs
#[session_test]
fn aes_xts_large_data_streaming(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    let dul = 1024;
    let plaintext = vec![0xAA; 64 * 1024];

    let (ct, _) = xts_encrypt_streaming(&key, &tweak, dul, &plaintext, &[dul * 2]).unwrap();
    assert_eq!(ct.len(), plaintext.len());

    let (pt, _) = xts_decrypt_streaming(&key, &tweak, dul, &ct, &[dul * 2]).unwrap();
    assert_eq!(pt, plaintext);
}

/// verifies decryption with a different tweak does not recover the original plaintext
#[session_test]
fn aes_xts_decrypt_with_wrong_tweak_fails_to_recover(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();

    let tweak1 = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let mut tweak2 = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    tweak2[0] = 1;

    let dul = 128;
    let plaintext = vec![0x44; dul * 2];

    let (ciphertext, _) = xts_encrypt(&key, &tweak1, dul, &plaintext).unwrap();

    let (decrypted, _) = xts_decrypt(&key, &tweak2, dul, &ciphertext).unwrap();

    assert_ne!(decrypted, plaintext);
}

/// verifies that different tweak values produce different ciphertext for identical plaintext
#[session_test]
fn aes_xts_higher_order_tweak_changes_ciphertext(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();

    let mut tweak1 = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let mut tweak2 = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    tweak1[7] = 1;
    tweak2[7] = 2;

    let dul = 256;
    let plaintext = vec![0x33; dul];

    let (ct1, _) = xts_encrypt(&key, &tweak1, dul, &plaintext).unwrap();
    let (ct2, _) = xts_encrypt(&key, &tweak2, dul, &plaintext).unwrap();

    assert_ne!(ct1, ct2);
}

/// verifies decrypt rejects ciphertext not aligned to the configured data-unit length
#[session_test]
fn aes_xts_decrypt_non_dul_aligned_ciphertext_rejected(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    let dul = 128;
    let plaintext = vec![0x55; dul * 2];

    let (mut ct, _) = xts_encrypt(&key, &tweak, dul, &plaintext).unwrap();

    ct.pop(); // break DUL alignment

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut out = vec![0u8; ct.len()];

    let err = algo.decrypt(&key, &ct, Some(&mut out)).unwrap_err();
    assert!(matches!(err, HsmError::InvalidArgument));
}

/// verifies streaming finish with no buffered data produces zero output
#[session_test]
fn aes_xts_streaming_finish_zero_output(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let enc_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = enc_algo.encrypt_init(key.clone()).unwrap();

    let out_len = ctx.finish(None).unwrap();
    assert_eq!(out_len, 0);

    let mut buf = [0u8; 1];
    let written = ctx.finish(Some(&mut buf)).unwrap();
    assert_eq!(written, 0);
}

/// verifies update size-query returns correct output size and enforces buffer requirements
#[session_test]
fn aes_xts_streaming_update_size_query_contract(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let enc_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = enc_algo.encrypt_init(key.clone()).unwrap();

    let block = vec![0x11; dul];

    let out_len = ctx.update(&block, None).unwrap();
    assert_eq!(out_len, dul);

    let mut too_small = vec![0u8; dul - 1];
    let err = ctx.update(&block, Some(&mut too_small)).unwrap_err();
    assert!(matches!(err, HsmError::BufferTooSmall));
}

/// verifies finish() on a fresh streaming context returns zero output
#[session_test]
fn aes_xts_finish_empty_stream_returns_zero(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut enc_ctx = algo.encrypt_init(key.clone()).unwrap();

    let mut out = vec![0u8; dul];

    // finish without update() should succeed and return 0 bytes
    let written = enc_ctx.finish(Some(&mut out)).unwrap();
    assert_eq!(written, 0);
}

/// verifies decrypting with a different key does not reproduce the original plaintext
#[session_test]
fn aes_xts_decrypt_with_wrong_key_fails_to_recover(session: HsmSession) {
    let key1 = aes_xts_generate_key(&session).unwrap();
    let key2 = aes_xts_generate_key(&session).unwrap();

    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 256;
    let plaintext = vec![0xAA; dul * 2];

    let (ciphertext, _) = xts_encrypt(&key1, &tweak, dul, &plaintext).unwrap();

    let (decrypted, _) = xts_decrypt(&key2, &tweak, dul, &ciphertext).unwrap();

    assert_ne!(decrypted, plaintext);
}

/// verifies encrypt and decrypt operations correctly handle zero-length inputs
#[session_test]
fn aes_xts_zero_length_input(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let plaintext: Vec<u8> = vec![];

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();

    let out_len = algo.encrypt(&key, &plaintext, None).unwrap();
    assert_eq!(out_len, 0);

    let mut out = vec![];
    let written = algo.encrypt(&key, &plaintext, Some(&mut out)).unwrap();
    assert_eq!(written, 0);

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let out_len = algo.decrypt(&key, &plaintext, None).unwrap();
    assert_eq!(out_len, 0);
}

/// verifies streaming update with empty input returns zero output
#[session_test]
fn aes_xts_streaming_empty_update(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = algo.encrypt_init(key).unwrap();

    let empty: [u8; 0] = [];
    let out_len = ctx.update(&empty, None).unwrap();
    assert_eq!(out_len, 0);
}

/// verifies size-query operations do not mutate the internal tweak state
#[session_test]
fn aes_xts_size_query_does_not_advance_tweak(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let plaintext = vec![0x11; dul * 2];

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let _ = algo.encrypt(&key, &plaintext, None).unwrap();

    assert_eq!(algo.tweak(), tweak.to_vec());
}

/// verifies streaming size-query does not advance the tweak state
#[session_test]
fn aes_xts_streaming_size_query_does_not_advance_tweak(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = algo.encrypt_init(key).unwrap();

    let block = vec![0x22; dul];

    let _ = ctx.update(&block, None).unwrap();
    assert_eq!(ctx.algo().tweak(), tweak.to_vec());
}

/// verifies finish does not modify the tweak state when no data remains
#[session_test]
fn aes_xts_finish_does_not_advance_tweak(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = algo.encrypt_init(key).unwrap();

    ctx.finish(None).unwrap();
    assert_eq!(ctx.algo().tweak(), tweak.to_vec());
}

/// verifies streaming decrypt rejects updates smaller than a full data unit
#[session_test]
fn aes_xts_streaming_decrypt_rejects_partial_data_unit(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 512;

    let dec_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut dec_ctx = dec_algo.decrypt_init(key).unwrap();

    let bad_chunk = [0x11u8; 1];
    let err = dec_ctx.update(&bad_chunk, None).unwrap_err();
    assert!(matches!(err, HsmError::InvalidArgument));
}

/// verifies decrypt update enforces minimum output buffer size
#[session_test]
fn aes_xts_streaming_decrypt_buffer_too_small(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 512;

    let dec_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut dec_ctx = dec_algo.decrypt_init(key).unwrap();

    let chunk = vec![0x11u8; dul];
    let mut too_small = vec![0u8; dul - 1];

    let err = dec_ctx.update(&chunk, Some(&mut too_small)).unwrap_err();
    assert!(matches!(err, HsmError::BufferTooSmall));
}

/// verifies tweak overflow during streaming decrypt is rejected
#[session_test]
fn aes_xts_streaming_decrypt_tweak_overflow_rejected(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let dul = 512;
    let tweak = u128::MAX.to_le_bytes();

    let dec_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut dec_ctx = dec_algo.decrypt_init(key).unwrap();

    let chunk = vec![0x22u8; dul];
    let mut out = vec![0u8; dul];

    let err = dec_ctx.update(&chunk, Some(&mut out)).unwrap_err();
    assert!(matches!(err, HsmError::InvalidTweak));
}

/// verifies constructor accepts the maximum supported data-unit length
#[test]
fn aes_xts_new_accepts_max_dul() {
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    assert!(HsmAesXtsAlgo::new(&tweak, 8192).is_ok());
}

/// verifies decrypt streaming update handles empty input without producing output
#[session_test]
fn aes_xts_streaming_empty_decrypt_update(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 128;

    let algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut ctx = algo.decrypt_init(key).unwrap();

    let empty: [u8; 0] = [];
    let out_len = ctx.update(&empty, None).unwrap();
    assert_eq!(out_len, 0);
}

/// verifies tweak overflow during streaming encrypt is rejected
#[session_test]
fn aes_xts_streaming_encrypt_tweak_overflow_rejected(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let dul = 512;
    let tweak = u128::MAX.to_le_bytes();

    let enc_algo = HsmAesXtsAlgo::new(&tweak, dul).unwrap();
    let mut enc_ctx = enc_algo.encrypt_init(key).unwrap();

    let chunk = vec![0x11u8; dul];
    let mut out = vec![0u8; dul];

    let err = enc_ctx.update(&chunk, Some(&mut out)).unwrap_err();
    assert!(matches!(err, HsmError::InvalidTweak));
}

/// verifies streaming works correctly when exactly one DUL is processed per update
#[session_test]
fn aes_xts_streaming_one_dul_per_update(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];
    let dul = 512;

    let units = 6;
    let plaintext = vec![0x66u8; dul * units];

    // streaming with exactly 1 DUL per update
    let chunk_sizes = [dul];

    let (single_ct, _) = xts_encrypt(&key, &tweak, dul, &plaintext).unwrap();

    let (stream_ct, stream_tweak_after) =
        xts_encrypt_streaming(&key, &tweak, dul, &plaintext, &chunk_sizes).unwrap();

    assert_eq!(stream_ct, single_ct);

    let (stream_pt, dec_tweak_after) =
        xts_decrypt_streaming(&key, &tweak, dul, &stream_ct, &chunk_sizes).unwrap();

    assert_eq!(stream_pt, plaintext);

    assert_eq!(stream_tweak_after, tweak_after_units(&tweak, units));

    assert_eq!(dec_tweak_after, tweak_after_units(&tweak, units));
}

/// verifies decrypting with a different DUL does not recover the original plaintext
#[session_test]
fn aes_xts_decrypt_with_different_dul_fails_to_recover(session: HsmSession) {
    let key = aes_xts_generate_key(&session).unwrap();
    let tweak = [0u8; AES_XTS_TEST_TWEAK_SIZE];

    let encrypt_dul = 256;
    let decrypt_dul = 512;

    let plaintext = vec![0x77; encrypt_dul * 2];

    // Encrypt using one DUL
    let (ciphertext, _) = xts_encrypt(&key, &tweak, encrypt_dul, &plaintext).unwrap();

    // Decrypt using a different DUL
    let (decrypted, _) = xts_decrypt(&key, &tweak, decrypt_dul, &ciphertext).unwrap();

    assert_ne!(decrypted, plaintext);
}
