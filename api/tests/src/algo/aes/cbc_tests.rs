// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

const AES_CBC_BLOCK_SIZE: usize = 16;

/// Create an AES-CBC algorithm instance configured for PKCS#7 padding (true) or no padding (false).
fn new_cbc_algo(padding: bool, iv: &[u8]) -> HsmAesCbcAlgo {
    if padding {
        HsmAesCbcAlgo::with_padding(iv.to_vec()).expect("Failed to create AES CBC algo")
    } else {
        HsmAesCbcAlgo::with_no_padding(iv.to_vec()).expect("Failed to create AES CBC algo")
    }
}

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

/// Encrypt then decrypt via AES-CBC and assert round-trip equality.
///
/// Notes:
/// - CBC mutates IV internally, so this helper always uses fresh algo instances.
/// - When `padding == false`, plaintext must be block-aligned and ciphertext length must match.
fn cbc_encrypt(key: &HsmAesKey, padding: bool, iv: &[u8], plaintext: &[u8]) -> HsmResult<Vec<u8>> {
    // Length query uses the algo and mutates IV, so use a fresh algo instance.
    let cipher_len = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, None)?
    };

    let mut out = vec![0u8; cipher_len];

    let written = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmEncrypter::encrypt(&mut algo, key, plaintext, Some(&mut out))?
    };
    out.truncate(written);

    Ok(out)
}

fn cbc_decrypt(key: &HsmAesKey, padding: bool, iv: &[u8], ciphertext: &[u8]) -> HsmResult<Vec<u8>> {
    // Length query uses the algo and mutates IV, so use a fresh algo instance.
    let max_plain_len = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, None)?
    };

    let mut out = vec![0xCCu8; max_plain_len];

    let written = {
        let mut algo = new_cbc_algo(padding, iv);
        HsmDecrypter::decrypt(&mut algo, key, ciphertext, Some(&mut out))?
    };
    out.truncate(written);

    Ok(out)
}
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

/// Basic AES-CBC no-padding roundtrip with a 128-bit key and 1-block plaintext.
#[session_test]
fn test_cbc_crypt_basic_no_pad_128(session: HsmSession) {
    let iv = [0x00u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x11u8; AES_CBC_BLOCK_SIZE];
    run_cbc_roundtrip(&session, 128, false, &iv, &plaintext);
}

/// Basic AES-CBC no-padding roundtrip with a 256-bit key and 1-block plaintext.
#[session_test]
fn test_cbc_crypt_basic_no_pad_256(session: HsmSession) {
    let iv = [0x10u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x22u8; AES_CBC_BLOCK_SIZE];
    run_cbc_roundtrip(&session, 256, false, &iv, &plaintext);
}

/// Basic AES-CBC PKCS#7 padding roundtrip with a 128-bit key and non-block-aligned plaintext.
#[session_test]
fn test_cbc_crypt_basic_pad_128(session: HsmSession) {
    let iv = [0x20u8; AES_CBC_BLOCK_SIZE];
    // Non-block-aligned input so padding is exercised.
    let plaintext = vec![0x33u8; AES_CBC_BLOCK_SIZE + 1];
    run_cbc_roundtrip(&session, 128, true, &iv, &plaintext);
}

/// Basic AES-CBC PKCS#7 padding roundtrip with a 256-bit key and non-block-aligned plaintext.
#[session_test]
fn test_cbc_crypt_basic_pad_256(session: HsmSession) {
    let iv = [0x30u8; AES_CBC_BLOCK_SIZE];
    // Non-block-aligned input so padding is exercised.
    let plaintext = vec![0x44u8; AES_CBC_BLOCK_SIZE + 1];
    run_cbc_roundtrip(&session, 256, true, &iv, &plaintext);
}

/// Large-data AES-CBC no-padding roundtrip (block-aligned) with a 128-bit key.
#[session_test]
fn test_cbc_crypt_large_no_pad_128(session: HsmSession) {
    let iv = [0x40u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xaau8; 4096]; // block-aligned
    run_cbc_roundtrip(&session, 128, false, &iv, &plaintext);
}

/// Large-data AES-CBC no-padding roundtrip (block-aligned) with a 256-bit key.
#[session_test]
fn test_cbc_crypt_large_no_pad_256(session: HsmSession) {
    let iv = [0x40u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xaau8; 4096]; // block-aligned
    run_cbc_roundtrip(&session, 256, false, &iv, &plaintext);
}

/// Large-data AES-CBC PKCS#7 padding roundtrip (non-block-aligned) with a 128-bit key.
#[session_test]
fn test_cbc_crypt_large_pad_128(session: HsmSession) {
    let iv = [0x50u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xaau8; 4096 + 7]; // non-boundary length
    run_cbc_roundtrip(&session, 128, true, &iv, &plaintext);
}

/// Large-data AES-CBC PKCS#7 padding roundtrip (non-block-aligned) with a 256-bit key.
#[session_test]
fn test_cbc_crypt_large_pad_256(session: HsmSession) {
    let iv = [0x50u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xaau8; 4096 + 10]; // non-boundary length
    run_cbc_roundtrip(&session, 256, true, &iv, &plaintext);
}

/// Padding length test: non-block-aligned plaintext should round up to the next block.
#[session_test]
fn test_cbc_encrypt_pad_ciphertext_len_non_boundary(session: HsmSession) {
    let iv = [0x23u8; AES_CBC_BLOCK_SIZE];
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
    let iv = [0x24u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x6Bu8; AES_CBC_BLOCK_SIZE * 2];

    let key = aes_generate_key(128, &session);
    let ciphertext = cbc_encrypt(&key, true, &iv, &plaintext).expect("Failed to encrypt");
    assert_eq!(ciphertext.len(), plaintext.len() + AES_CBC_BLOCK_SIZE);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Negative test: no-padding mode requires block-aligned plaintext; backend should return an error.
#[session_test]
fn test_cbc_encrypt_non_aligned_no_pad_fails(session: HsmSession) {
    let iv = [0x08u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x99u8; AES_CBC_BLOCK_SIZE + 1];

    let key = aes_generate_key(128, &session);
    let result = cbc_encrypt(&key, false, &iv, &plaintext);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Negative test: tamper with ciphertext (bit flip) and ensure decrypt does not reproduce plaintext.
///
/// CBC provides confidentiality only; without authentication, decryption can succeed but yield garbage.
#[session_test]
fn test_cbc_decrypt_tampered_ciphertext_no_pad_128(session: HsmSession) {
    let iv = [0x60u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x55u8; AES_CBC_BLOCK_SIZE];

    let key = aes_generate_key(128, &session);
    let mut ciphertext = cbc_encrypt(&key, false, &iv, &plaintext).expect("Failed to encrypt");
    ciphertext[0] ^= 0x01;

    let decrypted = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Decrypt should succeed");
    assert_ne!(decrypted, plaintext);
}

/// Negative test: tamper with ciphertext length (truncate) and ensure decrypt fails.
///
/// CBC requires ciphertext length to be a multiple of the block size.
#[session_test]
fn test_cbc_decrypt_truncated_ciphertext_fails(session: HsmSession) {
    let iv = [0x70u8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0x66u8; AES_CBC_BLOCK_SIZE + 1]; // padding enabled

    let key = aes_generate_key(128, &session);
    let mut ciphertext = cbc_encrypt(&key, true, &iv, &plaintext).expect("Failed to encrypt");
    ciphertext.pop();

    let result = cbc_decrypt(&key, true, &iv, &ciphertext);
    assert!(matches!(result, Err(HsmError::InvalidArgument)));
}

/// Negative test: AES-CBC requires a 16-byte IV; invalid IV length should be rejected.
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

/// Streaming tests
#[session_test]
fn test_cbc_streaming_no_pad_128(session: HsmSession) {
    let iv = [0xAAu8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xBBu8; 4096]; // block-aligned

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());

    let dec_buf = cbc_decrypt(&key, false, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(dec_buf, plaintext);
}

/// Streaming + padding length test: non-block-aligned plaintext should round up to the next block.
#[session_test]
fn test_cbc_streaming_pad_128_ciphertext_len_non_boundary(session: HsmSession) {
    let iv = [0xBAu8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xCAu8; 4096 + 7];

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, true, &iv, &plaintext, &[512])
        .expect("Failed to encrypt via streaming");
    let exp_cipher_len = ((plaintext.len() / AES_CBC_BLOCK_SIZE) + 1) * AES_CBC_BLOCK_SIZE;
    assert_eq!(ciphertext.len(), exp_cipher_len);

    let decrypted = cbc_decrypt(&key, true, &iv, &ciphertext).expect("Failed to decrypt");
    assert_eq!(decrypted, plaintext);
}

/// Streaming + padding length test: block-aligned plaintext should still add a full block of padding.
#[session_test]
fn test_cbc_streaming_pad_128_ciphertext_len_block_boundary(session: HsmSession) {
    let iv = [0xBBu8; AES_CBC_BLOCK_SIZE];
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

/// Single-shot encryption, streaming decryption (no padding, 128-bit key).
///
/// This validates that streaming decryption correctly buffers partial blocks
/// even when ciphertext chunk boundaries are not block-aligned.
#[session_test]
fn test_cbc_single_shot_encrypt_streaming_decrypt_no_pad_128(session: HsmSession) {
    let iv = [0xABu8; AES_CBC_BLOCK_SIZE];
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
    let iv = [0xACu8; AES_CBC_BLOCK_SIZE];
    let plaintext = vec![0xCDu8; 4096]; // block-aligned

    let key = aes_generate_streaming_key(128, &session);

    let ciphertext = cbc_encrypt_streaming(&key, false, &iv, &plaintext, &[17, 511, 1000, 33])
        .expect("Failed to encrypt via streaming");
    assert_eq!(ciphertext.len(), plaintext.len());

    let out = cbc_decrypt_streaming(&key, false, &iv, &ciphertext, &[1000, 7, 513, 64])
        .expect("Failed to decrypt via streaming");
    assert_eq!(out, plaintext);
}
