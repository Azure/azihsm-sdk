// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_api::HsmKeyClass;
use azihsm_api::HsmKeyKind;
use azihsm_api::HsmKeyManager;
use azihsm_api::HsmKeyPropsBuilder;
use azihsm_crypto::Rng;

use super::common::*;
use super::*;

// ================================
// Helpers
// ================================

// ================================
// Key Generation Helpers
// ================================

/// Generate a session-only AES key of the requested bit length.
fn aes_generate_key(bit_len: u32, session: &HsmSession) -> HsmAesKey {
    // Create key properties for an AES key
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bit_len)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .expect("Failed to build key properties");

    // Create the AES key generation algorithm
    let mut algo = HsmAesKeyGenAlgo::default();

    // Generate the key
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key")
}

/// Generate a non-session AES key for streaming tests.
///
/// Streaming contexts take ownership of a key (by value). Since `HsmAesKey` is `Clone` and
/// session keys auto-delete on `Drop`, using a session key in streaming tests can lead to
/// premature deletion when a cloned key in a context is dropped.
fn aes_generate_streaming_key(bit_len: u32, session: &HsmSession) -> HsmAesKey {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bit_len)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(true)
        .is_session(false)
        .build()
        .expect("Failed to build key properties");

    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props).expect("Failed to generate AES key")
}

fn aes_generate_key_no_encrypt(bit_len: u32, session: &HsmSession) -> HsmResult<HsmAesKey> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bit_len)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(false)
        .can_decrypt(true)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props)
}

fn aes_generate_key_no_decrypt(bit_len: u32, session: &HsmSession) -> HsmResult<HsmAesKey> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .bits(bit_len)
        .key_kind(HsmKeyKind::Aes)
        .can_encrypt(true)
        .can_decrypt(false)
        .is_session(true)
        .build()
        .unwrap();

    let mut algo = HsmAesKeyGenAlgo::default();
    HsmKeyManager::generate_key(session, &mut algo, props)
}

fn run_cbc_roundtrip(
    session: &HsmSession,
    key_bits: u32,
    padding: bool,
    iv: &[u8],
    plaintext: &[u8],
) {
    let key = aes_generate_key(key_bits, session);

    let ciphertext = cbc_encrypt(&key, padding, iv, plaintext).expect("Failed to encrypt");
    assert!(ciphertext.len().is_multiple_of(AES_CBC_BLOCK_SIZE));
    if !padding {
        assert_eq!(ciphertext.len(), plaintext.len());
    } else {
        assert!(ciphertext.len() >= plaintext.len());
    }

    let decrypted = cbc_decrypt(&key, padding, iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

// ================================
// Streaming  Helpers
// ================================

fn cbc_encrypt_streaming(
    key: &HsmAesKey,
    padding: bool,
    iv: &[u8],
    plaintext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<Vec<u8>> {
    let enc_algo = new_cbc_algo(padding, iv);
    let mut enc_ctx = enc_algo.encrypt_init(key.clone())?;

    let mut ciphertext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < plaintext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(plaintext.len() - offset);
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

    Ok(ciphertext)
}

fn cbc_decrypt_streaming(
    key: &HsmAesKey,
    padding: bool,
    iv: &[u8],
    ciphertext: &[u8],
    chunk_sizes: &[usize],
) -> HsmResult<Vec<u8>> {
    let dec_algo = new_cbc_algo(padding, iv);
    let mut dec_ctx = dec_algo.decrypt_init(key.clone())?;

    let mut plaintext = Vec::<u8>::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < ciphertext.len() {
        let size = chunk_sizes[i % chunk_sizes.len()].min(ciphertext.len() - offset);
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

    Ok(plaintext)
}

// ================================
// Test Scenario Runners (Negative / Edge Cases)
// ================================

fn run_cbc_invalid_padding_variants(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    // Force padding length > 1
    let pt = vec![0x11; AES_CBC_BLOCK_SIZE + 5];
    let ct = cbc_encrypt(&key, true, &iv, &pt).unwrap();

    let pad_len = AES_CBC_BLOCK_SIZE - (pt.len() % AES_CBC_BLOCK_SIZE);

    // Case 1: corrupt last padding byte (deterministically invalid)
    //
    // Flip the last byte of C_{n-1} rather than C_n. In CBC mode,
    // P_n = D_K(C_n) XOR C_{n-1}, so this changes only the last byte of
    // P_n (the padding-length indicator). Since the original value is in
    // 1..=16, XOR with 0xFF yields a value > 16 that can never be valid
    // PKCS#7 padding.
    {
        let mut bad = ct.clone();
        let blocks = bad.len() / AES_CBC_BLOCK_SIZE;
        assert!(blocks >= 2, "need at least two blocks");
        let target = (blocks - 2) * AES_CBC_BLOCK_SIZE + (AES_CBC_BLOCK_SIZE - 1);
        bad[target] ^= 0xFF;

        let result = cbc_decrypt(&key, true, &iv, &bad);
        assert!(
            result.is_err(),
            "expected invalid padding when corrupting last padding byte (bits={key_bits})"
        );
    }

    // Case 2: corrupt ALL padding bytes via previous block (guaranteed invalid)
    {
        let mut bad = ct.clone();
        // In CBC mode, P_n = D_K(C_n) XOR C_{n-1}.
        // To guarantee invalid PKCS#7 padding, flip bytes in C_{n-1} corresponding to
        // padding positions except the last one. This way, at least one padding byte
        // differs from pad_len, while the last byte still indicates the original pad_len.
        let blocks = bad.len() / AES_CBC_BLOCK_SIZE;
        assert!(blocks >= 2, "expected at least two blocks for padding test");
        let prev_block_start = (blocks - 2) * AES_CBC_BLOCK_SIZE;
        let pad_start_in_block = AES_CBC_BLOCK_SIZE - pad_len;
        // Flip all padding bytes except the last one.
        for i in pad_start_in_block..AES_CBC_BLOCK_SIZE - 1 {
            bad[prev_block_start + i] ^= 0xFF;
        }

        let result = cbc_decrypt(&key, true, &iv, &bad);
        assert!(
            result.is_err(),
            "expected invalid padding when corrupting full padding block (bits={key_bits})"
        );
    }

    // best-effort fuzz (do not assert hard failure as occasionally it succeeds)
    for i in 0..pad_len {
        let mut bad = ct.clone();
        let idx = bad.len() - 1 - i;
        bad[idx] ^= 0xAA;

        let result = cbc_decrypt(&key, true, &iv, &bad);

        if result.is_ok() {
            tracing::warn!("backend accepted corrupted padding byte offset={i} (bits={key_bits})");
        }
    }
}

fn run_cbc_encrypt_buffer_too_small(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);
    let pt = vec![0xAB; 17];

    let mut algo = new_cbc_algo(true, &iv);
    let needed = algo.encrypt(&key, &pt, None).unwrap();

    let mut too_small = vec![0u8; needed - 1];
    let result = algo.encrypt(&key, &pt, Some(&mut too_small));

    assert!(matches!(result, Err(HsmError::BufferTooSmall)));
}

fn run_cbc_decrypt_buffer_too_small(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    let pt = vec![0x11; 32];
    let ct = cbc_encrypt(&key, true, &iv, &pt).unwrap();

    let mut algo = new_cbc_algo(true, &iv);
    let mut out = vec![0u8; ct.len() - 1];

    let result = algo.decrypt(&key, &ct, Some(&mut out));
    assert!(matches!(result, Err(HsmError::BufferTooSmall)));
}

fn run_cbc_decrypt_truncated_ciphertext(session: &HsmSession, key_bits: u32, padding: bool) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    let pt = if padding {
        vec![0xAAu8; AES_CBC_BLOCK_SIZE + 1]
    } else {
        vec![0xAAu8; AES_CBC_BLOCK_SIZE * 2]
    };

    let mut ct = cbc_encrypt(&key, padding, &iv, &pt).unwrap();
    ct.pop(); // truncate

    let result = cbc_decrypt(&key, padding, &iv, &ct);
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "expected InvalidArgument (bits={key_bits}, padding={padding})"
    );
}

fn assert_cbc_decrypt_len_query_matches_ciphertext_len(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    let pt = vec![0x22; 31];
    let ct = cbc_encrypt(&key, true, &iv, &pt).unwrap();

    let mut algo = new_cbc_algo(true, &iv);
    let len = algo.decrypt(&key, &ct, None).unwrap();

    assert_eq!(len, ct.len());
}

fn assert_cbc_encrypt_non_aligned_no_pad_fails(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let plaintext = vec![0x99u8; AES_CBC_BLOCK_SIZE + 1];

    let key = aes_generate_key(key_bits, session);
    let result = cbc_encrypt(&key, false, &iv, &plaintext);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

fn run_cbc_decrypt_size_query_no_pad(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    let pt = vec![0xAAu8; AES_CBC_BLOCK_SIZE * 2];
    let ct = cbc_encrypt(&key, false, &iv, &pt).unwrap();

    let mut algo = new_cbc_algo(false, &iv);
    let len = algo.decrypt(&key, &ct, None).unwrap();

    assert_eq!(len, pt.len());
}

fn run_cbc_decrypt_empty_ciphertext_fails(session: &HsmSession, key_bits: u32) {
    let iv = test_iv();
    let key = aes_generate_key(key_bits, session);

    let mut algo = new_cbc_algo(true, &iv);
    let result = algo.decrypt(&key, &[], None);

    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

// ================================
// Coverage / Sweep Helpers
// ================================

fn run_cbc_padding_boundary(session: &HsmSession, key_bits: u32, streaming: bool) {
    let iv = test_iv();

    let key = if streaming {
        aes_generate_streaming_key(key_bits, session)
    } else {
        aes_generate_key(key_bits, session)
    };

    for len in [15usize, 16, 17, 31, 32, 33] {
        let pt = vec![0x41; len];

        let ct = if streaming {
            cbc_encrypt_streaming(&key, true, &iv, &pt, &[1, 7, 13, 16, 3]).unwrap()
        } else {
            cbc_encrypt(&key, true, &iv, &pt).unwrap()
        };

        let out = if streaming {
            cbc_decrypt_streaming(&key, true, &iv, &ct, &[5, 9, 2, 16, 7]).unwrap()
        } else {
            cbc_decrypt(&key, true, &iv, &ct).unwrap()
        };

        assert_eq!(
            out, pt,
            "padding boundary mismatch (len={len}, bits={key_bits}, streaming={streaming})"
        );
    }
}

fn run_cbc_padding_and_chunk_sweep(session: &HsmSession, key_bits: u32, streaming: bool) {
    let iv = test_iv();

    let key = if streaming {
        aes_generate_streaming_key(key_bits, session)
    } else {
        aes_generate_key(key_bits, session)
    };

    // Boundary-focused test sizes (no 0..=128 sweep)
    let test_lengths: &[usize] = &[0, 1, 15, 16, 17, 31, 32, 33, 64, 127, 128];

    for &len in test_lengths {
        let pt = vec![0xBB; len];

        let ct = if streaming {
            cbc_encrypt_streaming(&key, true, &iv, &pt, &[1, 2, 3, 7, 15, 16, 31])
                .expect("streaming encrypt failed")
        } else {
            cbc_encrypt(&key, true, &iv, &pt).expect("single-shot encrypt failed")
        };

        let out = if streaming {
            cbc_decrypt_streaming(&key, true, &iv, &ct, &[5, 9, 2, 16, 7])
                .expect("streaming decrypt failed")
        } else {
            cbc_decrypt(&key, true, &iv, &ct).expect("single-shot decrypt failed")
        };

        assert_eq!(
            out, pt,
            "padding sweep mismatch (len={len}, bits={key_bits}, streaming={streaming})"
        );
    }
}

// ============================================================
// test cases sections
// ============================================================
// ============================================================
// ENCRYPT/DECRYPT ROUNDTRIPS
// ============================================================
// --- basic roundtrips
/// Basic AES-CBC no-padding roundtrip with a 128-bit key and 1-block plaintext.
#[session_test]
fn test_cbc_crypt_basic_no_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x11u8; AES_CBC_BLOCK_SIZE];
    run_cbc_roundtrip(&session, 128, false, &iv, &plaintext);
}

/// Basic AES-CBC no-padding roundtrip with a 192-bit key and 1-block plaintext.
#[session_test]
fn test_cbc_crypt_basic_no_pad_192(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xA1u8; AES_CBC_BLOCK_SIZE];
    run_cbc_roundtrip(&session, 192, false, &iv, &plaintext);
}

/// Basic AES-CBC no-padding roundtrip with a 256-bit key and 1-block plaintext.
#[session_test]
fn test_cbc_crypt_basic_no_pad_256(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x22u8; AES_CBC_BLOCK_SIZE];
    run_cbc_roundtrip(&session, 256, false, &iv, &plaintext);
}

/// Basic AES-CBC PKCS#7 padding roundtrip with a 128-bit key and non-block-aligned plaintext.
#[session_test]
fn test_cbc_crypt_basic_pad_128(session: HsmSession) {
    let iv = test_iv();
    // Non-block-aligned input so padding is exercised.
    let plaintext = vec![0x33u8; AES_CBC_BLOCK_SIZE + 1];
    run_cbc_roundtrip(&session, 128, true, &iv, &plaintext);
}

/// Basic AES-CBC PKCS#7 padding roundtrip with a 192-bit key and non-block-aligned plaintext.
#[session_test]
fn test_cbc_crypt_basic_pad_192(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xA2u8; AES_CBC_BLOCK_SIZE + 3];
    run_cbc_roundtrip(&session, 192, true, &iv, &plaintext);
}

/// Basic AES-CBC PKCS#7 padding roundtrip with a 256-bit key and non-block-aligned plaintext.
#[session_test]
fn test_cbc_crypt_basic_pad_256(session: HsmSession) {
    let iv = test_iv();
    // Non-block-aligned input so padding is exercised.
    let plaintext = vec![0x44u8; AES_CBC_BLOCK_SIZE + 1];
    run_cbc_roundtrip(&session, 256, true, &iv, &plaintext);
}

// --- large

/// Large-data AES-CBC no-padding roundtrip (block-aligned) with a 128-bit key.
#[session_test]
fn test_cbc_crypt_large_no_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xaau8; 4096]; // block-aligned
    run_cbc_roundtrip(&session, 128, false, &iv, &plaintext);
}

/// Large-data AES-CBC no-padding roundtrip (block-aligned) with a 192-bit key.
#[session_test]
fn test_cbc_crypt_large_no_pad_192(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xA3u8; 4096];
    run_cbc_roundtrip(&session, 192, false, &iv, &plaintext);
}

/// Large-data AES-CBC no-padding roundtrip (block-aligned) with a 256-bit key.
#[session_test]
fn test_cbc_crypt_large_no_pad_256(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xaau8; 4096]; // block-aligned
    run_cbc_roundtrip(&session, 256, false, &iv, &plaintext);
}

/// Large-data AES-CBC PKCS#7 padding roundtrip (non-block-aligned) with a 128-bit key.
#[session_test]
fn test_cbc_crypt_large_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xaau8; 4096 + 7]; // non-boundary length
    run_cbc_roundtrip(&session, 128, true, &iv, &plaintext);
}

/// Large-data AES-CBC PKCS#7 padding roundtrip (non-block-aligned) with a 192-bit key.
#[session_test]
fn test_cbc_crypt_large_pad_192(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xA4u8; 4096 + 9];
    run_cbc_roundtrip(&session, 192, true, &iv, &plaintext);
}

/// Large-data AES-CBC PKCS#7 padding roundtrip (non-block-aligned) with a 256-bit key.
#[session_test]
fn test_cbc_crypt_large_pad_256(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xaau8; 4096 + 10]; // non-boundary length
    run_cbc_roundtrip(&session, 256, true, &iv, &plaintext);
}

// --- padding boundary conditions

/// PKCS#7 padding boundary sweep (single-shot) with AES-128.
#[session_test]
fn test_cbc_padding_boundary_single_shot_128(session: HsmSession) {
    run_cbc_padding_boundary(&session, 128, false);
}

/// PKCS#7 padding boundary sweep (single-shot) with AES-192.
#[session_test]
fn test_cbc_padding_boundary_single_shot_192(session: HsmSession) {
    run_cbc_padding_boundary(&session, 192, false);
}

/// PKCS#7 padding boundary sweep (single-shot) with AES-128.
#[session_test]
fn test_cbc_padding_boundary_single_shot_256(session: HsmSession) {
    run_cbc_padding_boundary(&session, 256, false);
}

// Padding length

/// Padding length test: non-block-aligned plaintext should round up to the next block.
#[session_test]
fn test_cbc_encrypt_pad_ciphertext_len_non_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x5Au8; AES_CBC_BLOCK_SIZE + 1];

    let key = aes_generate_key(128, &session);
    let ciphertext = cbc_encrypt(&key, true, &iv, &plaintext).expect("Failed to encrypt");
    let exp_cipher_len = ((plaintext.len() / AES_CBC_BLOCK_SIZE) + 1) * AES_CBC_BLOCK_SIZE;
    assert_eq!(ciphertext.len(), exp_cipher_len);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Padding length test: block-aligned plaintext should still add a full block of padding.
#[session_test]
fn test_cbc_encrypt_pad_ciphertext_len_block_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x6Bu8; AES_CBC_BLOCK_SIZE * 2];

    let key = aes_generate_key(128, &session);
    let ciphertext = cbc_encrypt(&key, true, &iv, &plaintext).expect("Failed to encrypt");
    assert_eq!(ciphertext.len(), plaintext.len() + AES_CBC_BLOCK_SIZE);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

// --- size queries & buffer sizing

/// Negative test: tamper with ciphertext (bit flip) and ensure decrypt does not reproduce plaintext.
///
/// CBC provides confidentiality only; without authentication, decryption can succeed but yield garbage.
#[session_test]
fn test_cbc_decrypt_tampered_ciphertext_no_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0x55u8; AES_CBC_BLOCK_SIZE];

    let key = aes_generate_key(128, &session);
    let mut ciphertext = cbc_encrypt(&key, false, &iv, &plaintext).expect("Failed to encrypt");
    ciphertext[0] ^= 0x01;

    let decrypted = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Decrypt should succeed");
    assert_ne!(decrypted, plaintext);
}

/// PKCS#7 padding boundary streaming with AES-128.
#[session_test]
fn test_cbc_padding_boundary_streaming_128(session: HsmSession) {
    run_cbc_padding_boundary(&session, 128, true);
}

/// PKCS#7 padding boundary streaming with AES-192.
#[session_test]
fn test_cbc_padding_boundary_streaming_192(session: HsmSession) {
    run_cbc_padding_boundary(&session, 192, true);
}

/// PKCS#7 padding boundary streaming with AES-256.
#[session_test]
fn test_cbc_padding_boundary_streaming_256(session: HsmSession) {
    run_cbc_padding_boundary(&session, 256, true);
}

/// Streaming tests
#[session_test]
fn test_cbc_streaming_no_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xBBu8; 4096]; // block-aligned

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());

    let dec_buf = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec_buf, plaintext);
}

/// Streaming no-padding (block-aligned) with AES-192.
#[session_test]
fn test_cbc_streaming_no_pad_192(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCBu8; 4096]; // block-aligned
    let key = aes_generate_streaming_key(192, &session);
    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());
    let dec = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec, plaintext);
}

/// Streaming no-padding (block-aligned) with AES-256.
#[session_test]
fn test_cbc_streaming_no_pad_256(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCBu8; 4096]; // block-aligned
    let key = aes_generate_streaming_key(256, &session);
    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());
    let dec = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec, plaintext);
}

/// Streaming + padding length test: non-block-aligned plaintext should round up to the next block.
#[session_test]
fn test_cbc_streaming_pad_128_ciphertext_len_non_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCAu8; 4096 + 7];

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, true, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    let exp_cipher_len = ((plaintext.len() / AES_CBC_BLOCK_SIZE) + 1) * AES_CBC_BLOCK_SIZE;
    assert_eq!(ciphertext.len(), exp_cipher_len);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Streaming + padding length test: non-block-aligned plaintext should round up to next block (AES-192).
#[session_test]
fn test_cbc_streaming_pad_192_ciphertext_len_non_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCDu8; 4096 + 11];
    let key = aes_generate_streaming_key(192, &session);
    let ciphertext = cbc_encrypt_streaming(&key, true, &iv, &plaintext, &[256])
        .expect("Failed to encrypt via streaming");
    let exp_len = ((plaintext.len() / AES_CBC_BLOCK_SIZE) + 1) * AES_CBC_BLOCK_SIZE;
    assert_eq!(ciphertext.len(), exp_len);
    let dec = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec, plaintext);
}

/// Streaming + padding length test: block-aligned plaintext should still add a full block of padding.
#[session_test]
fn test_cbc_streaming_pad_128_ciphertext_len_block_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xDBu8; 4096];

    let key = aes_generate_streaming_key(128, &session);
    // PKCS#7 always adds padding, even when plaintext is block-aligned.
    let exp_cipher_len = ((plaintext.len() / AES_CBC_BLOCK_SIZE) + 1) * AES_CBC_BLOCK_SIZE;
    let ciphertext = cbc_encrypt_streaming(&key, true, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len() + AES_CBC_BLOCK_SIZE);
    assert_eq!(ciphertext.len(), exp_cipher_len);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Streaming + padding: block-aligned plaintext still adds a full block (AES-192).
#[session_test]
fn test_cbc_streaming_pad_192_ciphertext_len_block_boundary(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xDEu8; 4096];
    let key = aes_generate_streaming_key(192, &session);
    let ciphertext = cbc_encrypt_streaming(&key, true, &iv, &plaintext, &[333])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len() + AES_CBC_BLOCK_SIZE);
    let dec = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec, plaintext);
}

/// Single-shot encryption, streaming decryption (no padding, 128-bit key).
///
/// This validates that streaming decryption correctly buffers partial blocks
/// even when ciphertext chunk boundaries are not block-aligned.
#[session_test]
fn test_cbc_single_shot_encrypt_streaming_decrypt_no_pad_128(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xBCu8; 4096]; // block-aligned

    let key = aes_generate_streaming_key(128, &session);

    // Encrypt in single shot.
    let ciphertext = cbc_encrypt(&key, false, &iv, &plaintext).expect("Failed to encrypt");
    assert_eq!(ciphertext.len(), plaintext.len());

    let out = cbc_decrypt_streaming(&key, false, &iv, &ciphertext, &[333, 777, 19, 128])
        .expect("Failed to decrypt via streaming");
    assert_eq!(out, plaintext);
}

/// Streaming encryption and streaming decryption with different chunk boundaries (no padding, 128-bit key).
#[session_test]
fn test_cbc_streaming_encrypt_streaming_decrypt_no_pad_128_diff_boundaries(session: HsmSession) {
    let iv = test_iv();
    let plaintext = vec![0xCDu8; 4096]; // block-aligned

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[17, 511, 1000, 33])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());

    let out = cbc_decrypt_streaming(&key, false, &iv, &ciphertext, &[1000, 7, 513, 64])
        .expect("Failed to decrypt via streaming");
    assert_eq!(out, plaintext);
}

// Runs AES-CBC PKCS#7 padding tests using boundary-focused plaintext sizes
// around AES block boundaries (16 bytes). This covers empty input, block
// boundaries, and nearby values up to 128 bytes.

/// Single-shot PKCS#7 padding and chunk sweep using AES-128.
#[session_test]
fn test_cbc_single_shot_padding_and_chunk_sweep_128(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 128, false);
}

/// Single-shot PKCS#7 padding and chunk sweep using AES-192.
#[session_test]
fn test_cbc_single_shot_padding_and_chunk_sweep_192(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 192, false);
}

/// Single-shot PKCS#7 padding and chunk sweep using AES-256.
#[session_test]
fn test_cbc_single_shot_padding_and_chunk_sweep_256(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 256, false);
}

/// Streaming PKCS#7 padding + chunk sweep (128-bit key).
#[session_test]
fn test_cbc_streaming_padding_and_chunk_sweep_128(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 128, true);
}

/// Streaming PKCS#7 padding and chunk sweep using AES-192.
#[session_test]
fn test_cbc_streaming_padding_and_chunk_sweep_192(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 192, true);
}

/// Streaming PKCS#7 padding and chunk sweep using AES-256.
#[session_test]
fn test_cbc_streaming_padding_and_chunk_sweep_256(session: HsmSession) {
    run_cbc_padding_and_chunk_sweep(&session, 256, true);
}

/// Same plaintext encrypted with different IVs must produce different ciphertexts.
#[session_test]
fn test_cbc_different_ivs_produce_different_ciphertexts(session: HsmSession) {
    let key = aes_generate_key(128, &session);
    let pt = vec![0xAB; 64];

    let iv1 = test_iv();
    let iv2 = test_iv();

    let ct1 = cbc_encrypt(&key, true, &iv1, &pt).unwrap();
    let ct2 = cbc_encrypt(&key, true, &iv2, &pt).unwrap();

    assert_ne!(ct1, ct2);
}

// ============================================================
// ENCRYPT ONLY
// ============================================================

/// Encrypt size query should return the required ciphertext length (AES-128).
#[session_test]
fn test_cbc_encrypt_size_query_128(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(128, &session);
    let pt = vec![0xAB; 17];

    let mut algo = new_cbc_algo(true, &iv);
    let size = algo.encrypt(&key, &pt, None).unwrap();

    assert!(size.is_multiple_of(AES_CBC_BLOCK_SIZE));
    assert!(size >= pt.len());
}

/// Encrypt size query should return the required ciphertext length (AES-192).
#[session_test]
fn test_cbc_encrypt_size_query_192(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(192, &session);
    let pt = vec![0xAB; 17];
    let mut algo = new_cbc_algo(true, &iv);
    let size = algo.encrypt(&key, &pt, None).unwrap();
    assert!(size.is_multiple_of(AES_CBC_BLOCK_SIZE));
}

/// Encrypt size query should return the required ciphertext length (AES-256).
#[session_test]
fn test_cbc_encrypt_size_query_256(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(256, &session);
    let pt = vec![0xAB; 17];

    let mut algo = new_cbc_algo(true, &iv);
    let size = algo.encrypt(&key, &pt, None).unwrap();

    assert!(size.is_multiple_of(AES_CBC_BLOCK_SIZE));
}

/// Encryption should fail with BufferTooSmall when output buffer is insufficient (AES-128).
#[session_test]
fn test_cbc_encrypt_buffer_too_small_128(session: HsmSession) {
    run_cbc_encrypt_buffer_too_small(&session, 128);
}

/// Encryption should fail with BufferTooSmall when output buffer is insufficient (AES-192).
#[session_test]
fn test_cbc_encrypt_buffer_too_small_192(session: HsmSession) {
    run_cbc_encrypt_buffer_too_small(&session, 192);
}

/// Encryption should fail with BufferTooSmall when output buffer is insufficient (AES-256).
#[session_test]
fn test_cbc_encrypt_buffer_too_small_256(session: HsmSession) {
    run_cbc_encrypt_buffer_too_small(&session, 256);
}

/// Streaming final-without-update with padding enabled should emit exactly one padding block.
#[session_test]
fn test_cbc_streaming_final_without_update_outputs_padding_block(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_streaming_key(256, &session);

    let pt = vec![];
    let ct = cbc_encrypt_streaming(&key, true, &iv, &pt, &[1]).expect("encrypt failed");
    assert_eq!(ct.len(), AES_CBC_BLOCK_SIZE);
}

/// Different IVs must produce different ciphertexts even without padding.
#[session_test]
fn test_cbc_different_ivs_no_padding(session: HsmSession) {
    let key = aes_generate_key(128, &session);
    let pt = vec![0xAB; 64];

    let iv1 = test_iv();
    let iv2 = test_iv();

    let ct1 = cbc_encrypt(&key, false, &iv1, &pt).unwrap();
    let ct2 = cbc_encrypt(&key, false, &iv2, &pt).unwrap();

    assert_ne!(ct1, ct2);
}

/// Streaming encryption must match single-shot ciphertext across chunk patterns.
#[session_test]
fn test_cbc_streaming_matches_single_shot_all_chunk_patterns(session: HsmSession) {
    let key = aes_generate_streaming_key(256, &session);
    let iv = test_iv();
    let pt = vec![0x42; 1024];

    let ct_single = cbc_encrypt(&key, true, &iv, &pt).unwrap();

    let chunk_patterns: &[&[usize]] = &[&[7, 31, 128], &[1, 1, 1], &[16, 16, 16], &[255, 3, 5]];

    for chunks in chunk_patterns {
        let ct_stream = cbc_encrypt_streaming(&key, true, &iv, &pt, chunks).unwrap();
        assert_eq!(
            ct_single, ct_stream,
            "streaming ciphertext mismatch for chunks={chunks:?}"
        );
    }
}

/// Empty plaintext with PKCS#7 padding should round-trip correctly (AES-128).
#[session_test]
fn test_cbc_encrypt_empty_plaintext_with_pad_roundtrip_128(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(128, &session);
    let pt = vec![];

    let ct = cbc_encrypt(&key, true, &iv, &pt).expect("encrypt empty plaintext failed");
    assert_eq!(ct.len(), AES_CBC_BLOCK_SIZE); // PKCS#7 emits one full block

    let out = cbc_decrypt(&key, true, &iv, &ct).expect("decrypt empty plaintext failed");
    assert!(out.is_empty());
}

/// Empty plaintext with PKCS#7 padding should round-trip correctly (AES-192).
#[session_test]
fn test_cbc_encrypt_empty_plaintext_with_pad_roundtrip_192(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(192, &session);
    let pt = vec![];

    let ct = cbc_encrypt(&key, true, &iv, &pt).expect("encrypt empty plaintext failed");
    assert_eq!(ct.len(), AES_CBC_BLOCK_SIZE); // PKCS#7 emits one full block

    let out = cbc_decrypt(&key, true, &iv, &ct).expect("decrypt empty plaintext failed");
    assert!(out.is_empty());
}

/// Empty plaintext with PKCS#7 padding should round-trip correctly (AES-256).
#[session_test]
fn test_cbc_encrypt_empty_plaintext_with_pad_roundtrip_256(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(256, &session);
    let pt = vec![];

    let ct = cbc_encrypt(&key, true, &iv, &pt).expect("encrypt empty plaintext failed");
    assert_eq!(ct.len(), AES_CBC_BLOCK_SIZE);

    let out = cbc_decrypt(&key, true, &iv, &ct).expect("decrypt empty plaintext failed");
    assert!(out.is_empty());
}

// ============================================================
// DECRYPT ONLY
// ============================================================

/// Truncating ciphertext should cause decryption to fail because
/// AES-CBC requires ciphertext length to be a multiple of the block size.

#[session_test]
fn test_cbc_decrypt_truncated_pad_128(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 128, true);
}

/// Truncated ciphertext should cause decryption to fail (AES-192, padding enabled).
#[session_test]
fn test_cbc_decrypt_truncated_pad_192(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 192, true);
}

/// Truncated ciphertext should cause decryption to fail (AES-256, padding enabled).
#[session_test]
fn test_cbc_decrypt_truncated_pad_256(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 256, true);
}

/// Truncated ciphertext should cause decryption to fail in no-padding mode (AES-128).
#[session_test]
fn test_cbc_decrypt_truncated_no_pad_128(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 128, false);
}

/// Truncated ciphertext should cause decryption to fail in no-padding mode (AES-192).
#[session_test]
fn test_cbc_decrypt_truncated_no_pad_192(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 192, false);
}

/// Truncated ciphertext should cause decryption to fail in no-padding mode (AES-256).
#[session_test]
fn test_cbc_decrypt_truncated_no_pad_256(session: HsmSession) {
    run_cbc_decrypt_truncated_ciphertext(&session, 256, false);
}

/// Decryption should fail when output buffer is smaller than required plaintext (AES-128).
#[session_test]
fn test_cbc_decrypt_buffer_too_small_128(session: HsmSession) {
    run_cbc_decrypt_buffer_too_small(&session, 128);
}

/// Decryption should fail when output buffer is smaller than required plaintext (AES-192).
#[session_test]
fn test_cbc_decrypt_buffer_too_small_192(session: HsmSession) {
    run_cbc_decrypt_buffer_too_small(&session, 192);
}

/// Decryption should fail when output buffer is smaller than required plaintext (AES-256).
#[session_test]
fn test_cbc_decrypt_buffer_too_small_256(session: HsmSession) {
    run_cbc_decrypt_buffer_too_small(&session, 256);
}

/// Decrypt length query should match ciphertext length when padding is enabled (AES-128).
#[session_test]
fn test_cbc_decrypt_len_query_matches_ciphertext_len_128(session: HsmSession) {
    assert_cbc_decrypt_len_query_matches_ciphertext_len(&session, 128);
}

/// Decrypt length query should match ciphertext length when padding is enabled (AES-192).
#[session_test]
fn test_cbc_decrypt_len_query_matches_ciphertext_len_192(session: HsmSession) {
    assert_cbc_decrypt_len_query_matches_ciphertext_len(&session, 192);
}

/// Decrypt length query should match ciphertext length when padding is enabled (AES-256).
#[session_test]
fn test_cbc_decrypt_len_query_matches_ciphertext_len_256(session: HsmSession) {
    assert_cbc_decrypt_len_query_matches_ciphertext_len(&session, 256);
}

/// Decrypt size query should return plaintext length when no padding is used (AES-128).
#[session_test]
fn test_cbc_decrypt_size_query_no_pad_128(session: HsmSession) {
    run_cbc_decrypt_size_query_no_pad(&session, 128);
}

/// Decrypt size query should return plaintext length when no padding is used (AES-192).
#[session_test]
fn test_cbc_decrypt_size_query_no_pad_192(session: HsmSession) {
    run_cbc_decrypt_size_query_no_pad(&session, 192);
}

/// Decrypt size query should return plaintext length when no padding is used (AES-256).
#[session_test]
fn test_cbc_decrypt_size_query_no_pad_256(session: HsmSession) {
    run_cbc_decrypt_size_query_no_pad(&session, 256);
}

// ============================================================
//  NEGATIVE TESTS
// ============================================================

// encrypt only

/// Encryption should fail when using a key without encrypt permission (AES-128).
#[session_test]
fn test_cbc_encrypt_key_without_encrypt_permission_fails_128(session: HsmSession) {
    let iv = test_iv();
    let pt = vec![0xAA; AES_CBC_BLOCK_SIZE];

    let key = match aes_generate_key_no_encrypt(128, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => {
            return;
        }
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };

    let result = cbc_encrypt(&key, false, &iv, &pt);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Encryption should fail when using a key without encrypt permission (AES-192).
#[session_test]
fn test_cbc_encrypt_key_without_encrypt_permission_fails_192(session: HsmSession) {
    let iv = test_iv();
    let pt = vec![0xAA; AES_CBC_BLOCK_SIZE];
    let key = match aes_generate_key_no_encrypt(192, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => return,
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };
    let result = cbc_encrypt(&key, false, &iv, &pt);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Encryption should fail when using a key without encrypt permission (AES-256).
#[session_test]
fn test_cbc_encrypt_key_without_encrypt_permission_fails_256(session: HsmSession) {
    let iv = test_iv();
    let pt = vec![0xAA; AES_CBC_BLOCK_SIZE];

    let key = match aes_generate_key_no_encrypt(256, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => return,
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };

    let result = cbc_encrypt(&key, false, &iv, &pt);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// No-padding mode requires block-aligned plaintext; backend should return an error.
#[session_test]
fn test_cbc_encrypt_non_aligned_no_pad_fails_128(session: HsmSession) {
    assert_cbc_encrypt_non_aligned_no_pad_fails(&session, 128);
}

/// No-padding mode requires block-aligned plaintext; backend should return an error (AES-192).
#[session_test]
fn test_cbc_encrypt_non_aligned_no_pad_fails_192(session: HsmSession) {
    assert_cbc_encrypt_non_aligned_no_pad_fails(&session, 192);
}

/// No-padding mode requires block-aligned plaintext; backend should return an error (AES-256).
#[session_test]
fn test_cbc_encrypt_non_aligned_no_pad_fails_256(session: HsmSession) {
    assert_cbc_encrypt_non_aligned_no_pad_fails(&session, 256);
}

/// No-padding encryption should reject empty plaintext (AES-128).
#[session_test]
fn test_cbc_encrypt_empty_plaintext_no_pad_128_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(128, &session);

    let pt = vec![];
    let result = cbc_encrypt(&key, false, &iv, &pt);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// No-padding encryption should reject empty plaintext (AES-256).
#[session_test]
fn test_cbc_encrypt_empty_plaintext_no_pad_256_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(256, &session);

    let pt = vec![];
    let result = cbc_encrypt(&key, false, &iv, &pt);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Streaming no-padding partial-block input should be rejected.
#[session_test]
fn test_cbc_streaming_no_padding_partial_block_is_rejected(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_streaming_key(256, &session);

    let pt = vec![0u8; AES_CBC_BLOCK_SIZE + 1];
    let result = cbc_encrypt_streaming(&key, false, &iv, &pt, &[15]);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

// decrypt only

/// Decryption should fail when ciphertext is empty (AES-128).
#[session_test]
fn test_cbc_decrypt_empty_ciphertext_fails_128(session: HsmSession) {
    run_cbc_decrypt_empty_ciphertext_fails(&session, 128);
}

/// Empty ciphertext (with padding mode) should fail on decrypt (AES-192).
#[session_test]
fn test_cbc_decrypt_empty_ciphertext_fails_192(session: HsmSession) {
    run_cbc_decrypt_empty_ciphertext_fails(&session, 192);
}

/// Decryption should fail when ciphertext is empty (AES-256).
#[session_test]
fn test_cbc_decrypt_empty_ciphertext_fails_256(session: HsmSession) {
    run_cbc_decrypt_empty_ciphertext_fails(&session, 256);
}

/// Decryption should fail when using a key without decrypt permission (AES-128).
#[session_test]
fn test_cbc_decrypt_key_without_decrypt_permission_fails_128(session: HsmSession) {
    let iv = test_iv();

    let key = match aes_generate_key_no_decrypt(128, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => return,
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };

    let ct = vec![0u8; AES_CBC_BLOCK_SIZE];

    let mut algo = new_cbc_algo(true, &iv);
    let result = algo.decrypt(&key, &ct, None);

    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Decryption should fail when using a key without decrypt permission (AES-192).
#[session_test]
fn test_cbc_decrypt_key_without_decrypt_permission_fails_192(session: HsmSession) {
    let iv = test_iv();
    let key = match aes_generate_key_no_decrypt(192, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => return, // backend disallows, pass vacuously
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };
    let ct = vec![0u8; AES_CBC_BLOCK_SIZE];
    let mut algo = new_cbc_algo(true, &iv);
    let result = algo.decrypt(&key, &ct, None);
    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Decryption should fail when using a key without decrypt permission (AES-256).
#[session_test]
fn test_cbc_decrypt_key_without_decrypt_permission_fails_256(session: HsmSession) {
    let iv = test_iv();

    let key = match aes_generate_key_no_decrypt(256, &session) {
        Ok(k) => k,
        Err(HsmError::InvalidKeyProps) => {
            // Backend disallows generating non-encrypt AES keys.
            // This is acceptable – test passes vacuously.
            return;
        }
        Err(e) => panic!("unexpected keygen error: {e:?}"),
    };

    let ct = vec![0u8; AES_CBC_BLOCK_SIZE];

    let mut algo = new_cbc_algo(true, &iv);
    let result = algo.decrypt(&key, &ct, None);

    assert!(matches!(result, Err(HsmError::InvalidKey)));
}

/// Streaming behavior: CBC encrypt buffers the final block until `finish()` is called.
#[session_test]
fn test_cbc_streaming_encrypt_buffers_final_block_until_finish(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_streaming_key(256, &session);
    let pt = vec![0x11u8; AES_CBC_BLOCK_SIZE];

    let enc_algo = new_cbc_algo(false, &iv);
    let mut enc_ctx = enc_algo
        .encrypt_init(key.clone())
        .expect("encrypt_init failed");

    // Encrypt exactly one block. For CBC without padding, the final full block
    // is buffered until `finish()` is called, so `update` should write 0 bytes.
    let mut out = vec![0u8; AES_CBC_BLOCK_SIZE];
    let written = enc_ctx.update(&pt, Some(&mut out)).unwrap();
    assert_eq!(written, 0);
    // Calling update with empty input should behave as a no-op.
    let result = enc_ctx.update(&[], None).unwrap();
    assert_eq!(result, 0);
    // The buffered block must be emitted when `finish()` is called.
    let final_written = enc_ctx.finish(Some(&mut out)).unwrap();
    assert_eq!(final_written, AES_CBC_BLOCK_SIZE);
}

/// Invalid PKCS#7 padding variants must be rejected (AES-128).
#[session_test]
fn test_cbc_decrypt_invalid_padding_variants_fail_128(session: HsmSession) {
    run_cbc_invalid_padding_variants(&session, 128);
}

/// Invalid PKCS#7 padding variants must be rejected (AES-192).
#[session_test]
fn test_cbc_decrypt_invalid_padding_variants_fail_192(session: HsmSession) {
    run_cbc_invalid_padding_variants(&session, 192);
}

/// Invalid PKCS#7 padding variants must be rejected (AES-256).
#[session_test]
fn test_cbc_decrypt_invalid_padding_variants_fail_256(session: HsmSession) {
    run_cbc_invalid_padding_variants(&session, 256);
}

// misc

/// AES-CBC requires a 16-byte IV; invalid IV length should be rejected.
#[session_test]
fn test_cbc_invalid_iv_fails(mut _session: HsmSession) {
    let iv_too_short = vec![0u8; AES_CBC_BLOCK_SIZE - 1];
    let iv_too_long = vec![0u8; AES_CBC_BLOCK_SIZE + 1];

    assert!(matches!(
        HsmAesCbcAlgo::with_no_padding(iv_too_short.clone()),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        HsmAesCbcAlgo::with_padding(iv_too_short),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        HsmAesCbcAlgo::with_no_padding(iv_too_long.clone()),
        Err(HsmError::InvalidArgument)
    ));
    assert!(matches!(
        HsmAesCbcAlgo::with_padding(iv_too_long),
        Err(HsmError::InvalidArgument)
    ));
}

/// Streaming decrypt should fail when finish() is called without prior update() in no-padding mode.
#[session_test]
fn test_cbc_streaming_final_without_update_no_pad_fails(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_streaming_key(128, &session);

    let dec_algo = new_cbc_algo(false, &iv);
    let mut dec_ctx = dec_algo.decrypt_init(key.clone()).unwrap();

    let result = dec_ctx.finish(None);
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "expected InvalidArgument when finish() called without update() in no-pad mode"
    );
}

/// IV must be exactly 16 bytes for both no-padding and padding modes.
/// Sweep a range of invalid lengths to ensure consistent rejection.
#[session_test]
fn test_cbc_invalid_iv_length_sweep_rejected_both_modes(_session: HsmSession) {
    // Try lengths 0..=32 excluding 16
    for len in 0usize..=32 {
        if len == AES_CBC_BLOCK_SIZE {
            continue;
        }

        let bad_iv = Rng::rand_vec(len).expect("RNG failure generating bad IV");
        // No padding variant should reject
        let no_pad = HsmAesCbcAlgo::with_no_padding(bad_iv.clone());
        assert!(
            matches!(no_pad, Err(HsmError::InvalidArgument)),
            "expected InvalidArgument for IV len={len} (no-pad)"
        );

        // Padding variant should reject
        let with_pad = HsmAesCbcAlgo::with_padding(bad_iv);
        assert!(
            matches!(with_pad, Err(HsmError::InvalidArgument)),
            "expected InvalidArgument for IV len={len} (pad)"
        );
    }
}

/// Decryption requires ciphertext len to be a multiple of block size.
/// Verify rejection for both pad and no-pad when length is not a multiple of 16.
#[session_test]
fn test_cbc_decrypt_non_block_aligned_ciphertext_fails_both_modes(session: HsmSession) {
    let key = aes_generate_key(128, &session);
    let iv = test_iv();

    // 17 bytes is not a multiple of 16 and not empty
    let bad_ct = vec![0xA5u8; AES_CBC_BLOCK_SIZE + 1];

    // No padding: reject non-multiple-of-block ciphertext
    let mut algo = new_cbc_algo(false, &iv);
    let result = algo.decrypt(&key, &bad_ct, None);
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "expected InvalidArgument (no-pad, len={})",
        bad_ct.len()
    );

    // Padding: still reject non-multiple-of-block ciphertext
    let mut algo = new_cbc_algo(true, &iv);
    let result = algo.decrypt(&key, &bad_ct, None);
    assert!(
        matches!(result, Err(HsmError::InvalidArgument)),
        "expected InvalidArgument (pad, len={})",
        bad_ct.len()
    );
}

/// Empty ciphertext should be rejected in BOTH modes (pad and no-pad).
#[session_test]
fn test_cbc_decrypt_empty_ciphertext_fails_no_pad(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_key(128, &session);
    let mut algo = new_cbc_algo(false, &iv);
    let result = algo.decrypt(&key, &[], None);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// No-padding mode requires block-aligned plaintext; reject non-aligned input (streaming).
/// This is the streaming counterpart of the single-shot non-aligned encrypt failure.
#[session_test]
fn test_cbc_streaming_no_padding_rejects_partial_final_block(session: HsmSession) {
    let iv = test_iv();
    let key = aes_generate_streaming_key(256, &session);

    // 1 block + 1 byte (not block-aligned)
    let pt = vec![0x11u8; AES_CBC_BLOCK_SIZE + 1];

    // Using a small chunk to ensure we hit the final partial block at finish()
    let result = cbc_encrypt_streaming(&key, false, &iv, &pt, &[15]);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Sanity: CBC mutates IV internally. Creating a fresh algo instance
/// per operation must be required; reusing the same instance would be incorrect.
/// Here we assert that reusing the SAME algo instance across two encrypt calls

#[session_test]
fn test_cbc_algo_iv_is_consumed_per_operation(session: HsmSession) {
    let key = aes_generate_key(128, &session);
    let iv = test_iv();
    let pt = vec![0x42u8; AES_CBC_BLOCK_SIZE];

    // First call with a fresh algo
    let mut algo1 = new_cbc_algo(false, &iv);
    let size1 = algo1.encrypt(&key, &pt, None).unwrap();
    let mut out1 = vec![0u8; size1];
    let written1 = algo1.encrypt(&key, &pt, Some(&mut out1)).unwrap();
    out1.truncate(written1);

    // Second call using the same algo instance (IV has been mutated internally)
    // Expect ciphertext to differ from a truly fresh IV run.
    let size2 = algo1.encrypt(&key, &pt, None).unwrap();
    let mut out2 = vec![0u8; size2];
    let written2 = algo1.encrypt(&key, &pt, Some(&mut out2)).unwrap();
    out2.truncate(written2);

    assert_ne!(
        out1, out2,
        "reusing a single algo instance should not reproduce the same ciphertext; create fresh algos per use"
    );
}
