// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use super::*;
use crate::aes::tests::testvectors::*;

fn tweak_as_u64(tweak: &[u8]) -> u64 {
    let bytes: [u8; 8] = tweak
        .try_into()
        .unwrap_or_else(|_| panic!("expected 8-byte tweak, got {}", tweak.len()));
    u64::from_le_bytes(bytes)
}

fn tweak_from_u64(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

fn make_aes_128_xts_key(k1: u8, k2: u8) -> AesXtsKey {
    let mut key_bytes = [0u8; 32];
    key_bytes[..16].fill(k1);
    key_bytes[16..].fill(k2);
    AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-128-XTS key")
}

fn assert_xts_tweak_advanced_single_shot(
    is_encrypt: bool,
    key: &AesXtsKey,
    start_tweak: u64,
    data_unit_len: usize,
    units: usize,
) {
    let tweak = tweak_from_u64(start_tweak);
    let len = data_unit_len * units;

    let input = vec![0x42u8; len];
    let mut output = vec![0u8; len];
    let mut aes_xts =
        AesXtsAlgo::new(&tweak, data_unit_len).expect("Failed to create AES-XTS algo");

    let result = if is_encrypt {
        aes_xts.encrypt(key, &input, Some(&mut output))
    } else {
        aes_xts.decrypt(key, &input, Some(&mut output))
    };

    result.unwrap_or_else(|e| {
        panic!(
            "AES-XTS {} failed: {:?}",
            if is_encrypt { "encrypt" } else { "decrypt" },
            e
        )
    });

    assert_eq!(tweak_as_u64(&aes_xts.tweak()), start_tweak + units as u64);
}

/// Helper function to verify key size and bits
fn verify_key_size(key: &AesXtsKey, expected_size: usize) {
    assert_eq!(key.size(), expected_size);
    assert_eq!(key.bits(), expected_size * 8);
}

/// Helper function to test key generation for a given size
fn test_key_generation(key_size: usize) {
    let key = AesXtsKey::generate(key_size)
        .unwrap_or_else(|_| panic!("Failed to generate AES-XTS key of size {}", key_size));
    verify_key_size(&key, key_size);
}

/// Helper function to test key creation from bytes
fn test_key_from_bytes(key_size: usize, pattern: u8) {
    let mut key_bytes = vec![pattern; key_size];
    //change k2 to different pattern
    key_bytes[key_size / 2..].fill(pattern.wrapping_add(2));

    let key = AesXtsKey::from_bytes(&key_bytes)
        .unwrap_or_else(|_| panic!("Failed to create AES-XTS key from bytes"));
    verify_key_size(&key, key_size);
}

/// Helper function to test invalid key size error
fn expect_invalid_key_size_error(result: Result<AesXtsKey, CryptoError>) {
    assert!(result.is_err());
    match result {
        Err(CryptoError::AesXtsInvalidKeySize) => {
            // Expected error
        }
        Err(e) => panic!("Expected AesXtsInvalidKeySize error, got {:?}", e),
        Ok(_) => panic!("Expected error for invalid key size"),
    }
}

/// Helper function to test key export
fn test_key_export(key_bytes: &[u8]) {
    let key = AesXtsKey::from_bytes(key_bytes).expect("Failed to create key");
    let key_size = key_bytes.len();

    // Get required size
    let size = key.to_bytes(None).expect("Failed to get key size");
    assert_eq!(size, key_size);

    // Export key
    let mut exported = vec![0u8; key_size];
    let exported_size = key
        .to_bytes(Some(&mut exported))
        .expect("Failed to export key");
    assert_eq!(exported_size, key_size);
    assert_eq!(exported, key_bytes);
}

/// Helper function to test AES-XTS encryption
/// Panics if encryption fails or output doesn't match expected ciphertext
fn test_xts_encrypt(
    test_count_id: u32,
    key: &AesXtsKey,
    tweak: &[u8],
    plaintext: &[u8],
    expected_ciphertext: &[u8],
) {
    let mut aes_xts =
        AesXtsAlgo::new(tweak, plaintext.len()).expect("Failed to create AES-XTS algo");
    let mut ciphertext = vec![0u8; plaintext.len()];

    let encrypted_len = aes_xts
        .encrypt(key, plaintext, Some(&mut ciphertext))
        .unwrap_or_else(|e| {
            panic!(
                "Vector {} - AES-XTS encryption failed: {:?}",
                test_count_id, e
            )
        });

    assert!(
        encrypted_len == plaintext.len(),
        "Vector {} - Encrypted length mismatch: got {}, expected {}",
        test_count_id,
        encrypted_len,
        plaintext.len()
    );

    assert!(
        &ciphertext[..encrypted_len] == expected_ciphertext,
        "Vector {} - Ciphertext mismatch\nExpected: {:02x?}\nActual:   {:02x?}",
        test_count_id,
        expected_ciphertext,
        &ciphertext[..encrypted_len]
    );
}

/// Helper function to test AES-XTS decryption
/// Panics if decryption fails or output doesn't match expected plaintext
fn test_xts_decrypt(
    test_count_id: u32,
    key: &AesXtsKey,
    tweak: &[u8],
    ciphertext: &[u8],
    expected_plaintext: &[u8],
) {
    let mut aes_xts =
        AesXtsAlgo::new(tweak, ciphertext.len()).expect("Failed to create AES-XTS algo");
    let mut decrypted = vec![0u8; ciphertext.len()];

    let decrypted_len = aes_xts
        .decrypt(key, ciphertext, Some(&mut decrypted))
        .unwrap_or_else(|e| {
            panic!(
                "Vector {} - AES-XTS decryption failed: {:?}",
                test_count_id, e
            )
        });

    assert!(
        decrypted_len == ciphertext.len(),
        "Vector {} - Decrypted length mismatch: got {}, expected {}",
        test_count_id,
        decrypted_len,
        ciphertext.len()
    );

    assert!(
        &decrypted[..decrypted_len] == expected_plaintext,
        "Vector {} - Plaintext mismatch\nExpected: {:02x?}\nActual:   {:02x?}",
        test_count_id,
        expected_plaintext,
        &decrypted[..decrypted_len]
    );
}

/// Helper function to perform streaming encryption
/// Returns the ciphertext and asserts the total length matches input
fn test_xts_streaming_encrypt(
    key: &AesXtsKey,
    tweak: &[u8],
    plaintext: &[u8],
    data_unit_len: usize,
    chunk_sizes: &[usize],
) -> Vec<u8> {
    let algo = AesXtsAlgo::new(tweak, data_unit_len).expect("Failed to create AES-XTS algo");
    let mut encrypt_ctx = algo
        .encrypt_init(key.clone())
        .expect("Failed to initialize encryption context");

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut total_encrypted = 0;
    let mut offset = 0;

    // Process chunks
    for &chunk_size in chunk_sizes {
        let end = (offset + chunk_size).min(plaintext.len());
        let chunk = &plaintext[offset..end];

        let encrypted = encrypt_ctx
            .update(chunk, Some(&mut ciphertext[total_encrypted..]))
            .unwrap_or_else(|e| {
                panic!(
                    "Streaming encryption update failed at offset {}: {:?}",
                    offset, e
                )
            });

        total_encrypted += encrypted;
        offset = end;
    }

    // Finalize
    let encrypted_final = encrypt_ctx
        .finish(Some(&mut ciphertext[total_encrypted..]))
        .expect("Streaming encryption finish failed");
    total_encrypted += encrypted_final;

    assert_eq!(
        total_encrypted,
        plaintext.len(),
        "Streaming encryption total length mismatch"
    );

    ciphertext
}

/// Helper function to perform streaming decryption
/// Returns the plaintext and asserts the total length matches input
fn test_xts_streaming_decrypt(
    key: &AesXtsKey,
    tweak: &[u8],
    ciphertext: &[u8],
    data_unit_len: usize,
    chunk_sizes: &[usize],
) -> Vec<u8> {
    let algo = AesXtsAlgo::new(tweak, data_unit_len).expect("Failed to create AES-XTS algo");
    let mut decrypt_ctx = algo
        .decrypt_init(key.clone())
        .expect("Failed to initialize decryption context");

    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut total_decrypted = 0;
    let mut offset = 0;

    // Process chunks
    for &chunk_size in chunk_sizes {
        let end = (offset + chunk_size).min(ciphertext.len());
        let chunk = &ciphertext[offset..end];

        let decrypted = decrypt_ctx
            .update(chunk, Some(&mut plaintext[total_decrypted..]))
            .unwrap_or_else(|e| {
                panic!(
                    "Streaming decryption update failed at offset {}: {:?}",
                    offset, e
                )
            });

        total_decrypted += decrypted;
        offset = end;
    }

    // Finalize
    let decrypted_final = decrypt_ctx
        .finish(Some(&mut plaintext[total_decrypted..]))
        .expect("Streaming decryption finish failed");
    total_decrypted += decrypted_final;

    assert_eq!(
        total_decrypted,
        ciphertext.len(),
        "Streaming decryption total length mismatch"
    );

    plaintext
}

/// Helper function to test that encryption or decryption fails with expected error
fn expect_xts_error(
    is_encrypt: bool,
    key_bytes: &[u8],
    tweak: &[u8],
    input: &[u8],
    expected_error: CryptoError,
) {
    let aes_xts_key = AesXtsKey::from_bytes(key_bytes).expect("Failed to create key");
    let mut aes_xts = match AesXtsAlgo::new(tweak, input.len()) {
        Ok(algo) => algo,
        Err(e) => {
            assert_eq!(e, expected_error);
            return;
        }
    };
    let mut output = vec![0u8; input.len()];

    let result = if is_encrypt {
        aes_xts.encrypt(&aes_xts_key, input, Some(&mut output))
    } else {
        aes_xts.decrypt(&aes_xts_key, input, Some(&mut output))
    };

    assert!(result.is_err(), "Expected error but got success");

    let error = result.unwrap_err();
    assert_eq!(error, expected_error);
}

#[test]
fn test_aes_xts_128_key_generation() {
    // AES-128-XTS requires 32 bytes (two 16-byte keys)
    test_key_generation(32);
}

#[test]
fn test_aes_xts_256_key_generation() {
    // AES-256-XTS requires 64 bytes (two 32-byte keys)
    test_key_generation(64);
}

#[test]
fn test_aes_xts_key_from_bytes_128() {
    test_key_from_bytes(32, 0x42);
}

#[test]
fn test_aes_xts_key_from_bytes_256() {
    test_key_from_bytes(64, 0xAA);
}

#[test]
fn test_aes_xts_key_invalid_size() {
    // Test invalid key size (not 32 or 64 bytes)
    let result = AesXtsKey::generate(16);
    expect_invalid_key_size_error(result);
}

#[test]
fn test_aes_xts_key_from_bytes_invalid_size() {
    let key_bytes = vec![0x42; 48]; // Invalid size (not 32 or 64)
    let result = AesXtsKey::from_bytes(&key_bytes);
    expect_invalid_key_size_error(result);
}

#[test]
fn test_aes_xts_key_export_128() {
    let mut key_bytes = vec![0x55; 32];
    key_bytes[16..].fill(0x56);
    test_key_export(key_bytes.as_ref());
}

#[test]
fn test_aes_xts_key_export_256() {
    let mut key_bytes = vec![0x77; 64];
    key_bytes[32..].fill(0x78);
    test_key_export(key_bytes.as_ref());
}

#[test]
fn test_aes_xts_key_export_buffer_too_small() {
    let mut key_bytes = vec![0x99; 32];
    key_bytes[16..].fill(0x9a);
    let key = AesXtsKey::from_bytes(&key_bytes).expect("Failed to create key");

    // Try to export with too small buffer
    let mut small_buffer = vec![0u8; 16];
    let result = key.to_bytes(Some(&mut small_buffer));

    assert!(result.is_err());
    match result {
        Err(CryptoError::AesXtsBufferTooSmall) => {
            // Expected error
        }
        Err(e) => panic!("Expected AesXtsBufferTooSmall error, got {:?}", e),
        Ok(_) => panic!("Expected error for buffer too small"),
    }
}

#[test]
fn test_aes_xts_256_encrypt_decrypt() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c, 0xd6, 0xe1, 0x3f, 0xfd, 0xf2, 0x41, 0x8d, 0x8d, 0x19, 0x11, 0xc0, 0x04, 0xcd,
        0xa5, 0x8d, 0xa3, 0xd6, 0x19, 0xb7, 0xe2, 0xb9, 0x14, 0x1e, 0x58, 0x31, 0x8e, 0xea, 0x39,
        0x2c, 0xf4, 0x1b, 0x08,
    ];
    let tweak = [0xad, 0xf8, 0xd9, 0x26, 0x27, 0x46, 0x4a, 0xd2];
    let plaintext = [
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1, 0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3,
        0x64, 0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3, 0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a,
        0x20, 0x2e,
    ];

    let aes_key = AesXtsKey::from_bytes(&key).expect("Failed to create AES-XTS key");

    // Encrypt to get ciphertext
    let mut aes_xts =
        AesXtsAlgo::new(&tweak, plaintext.len()).expect("Failed to create AES-XTS algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let encrypted_len = aes_xts
        .encrypt(&aes_key, &plaintext, Some(&mut ciphertext))
        .expect("AES-XTS encryption failed");
    assert_eq!(encrypted_len, plaintext.len());

    // Verify encryption is deterministic using helper
    test_xts_encrypt(0, &aes_key, &tweak, &plaintext, &ciphertext);

    // Verify decryption using helper
    test_xts_decrypt(0, &aes_key, &tweak, &ciphertext, &plaintext);
}

#[test]
fn test_aes_xts_128_encrypt_decrypt() {
    let key: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let tweak: [u8; 8] = [0x01, 0x02, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
    let plaintext: [u8; 32] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
        0x5f, 0x60,
    ];
    let aes_xts_key = AesXtsKey::from_bytes(&key).expect("Failed to import key bytes");

    // Encrypt to get ciphertext
    let mut aes_xts =
        AesXtsAlgo::new(&tweak, plaintext.len()).expect("Failed to create AES-XTS algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    println!("original tweak: {:02x?}", &tweak);
    let encrypted_len = aes_xts
        .encrypt(&aes_xts_key, &plaintext, Some(&mut ciphertext))
        .expect("AES-XTS encryption failed");
    println!("tweak: {:02x?}", aes_xts.tweak());
    assert_eq!(encrypted_len, plaintext.len());

    // Verify encryption is deterministic using helper
    test_xts_encrypt(0, &aes_xts_key, &tweak, &plaintext, &ciphertext);

    // Verify decryption using helper
    test_xts_decrypt(0, &aes_xts_key, &tweak, &ciphertext, &plaintext);
}

#[test]
fn test_aes_xts_tweak_increments_single_shot_encrypt() {
    // XTS uses two AES keys; OSSL  reject key1 == key2.
    let aes_xts_key = make_aes_128_xts_key(0x11, 0x22);

    assert_xts_tweak_advanced_single_shot(true, &aes_xts_key, 7, 32, 3);
}

#[test]
fn test_aes_xts_tweak_increments_single_shot_decrypt() {
    // XTS uses two AES keys; OSSL  reject key1 == key2.
    let aes_xts_key = make_aes_128_xts_key(0x33, 0x44);

    assert_xts_tweak_advanced_single_shot(false, &aes_xts_key, 123, 32, 2);
}

#[test]
fn test_aes_xts_tweak_increments_streaming_encrypt_update_then_finish() {
    // XTS uses two AES keys; OSSL  reject key1 == key2.
    let aes_xts_key = make_aes_128_xts_key(0x55, 0x66);

    let data_unit_len = 32;
    let units = 2usize;
    let plaintext = vec![0xabu8; data_unit_len * units];

    let start = 0u64;
    let tweak = tweak_from_u64(start);

    let algo = AesXtsAlgo::new(&tweak, data_unit_len).expect("Failed to create AES-XTS algo");
    let mut ctx = algo
        .encrypt_init(aes_xts_key)
        .expect("Failed to initialize encryption context");

    let mut out = vec![0u8; plaintext.len()];

    // `update()` accepts input sizes that are multiples of `dul`.
    // Different backends may buffer differently across update()/finish(), so assert totals + final tweak.
    let written_update = ctx
        .update(&plaintext, Some(&mut out))
        .expect("Streaming encrypt update failed");
    assert!(written_update.is_multiple_of(data_unit_len));
    assert!(written_update <= plaintext.len());

    let written_finish = ctx
        .finish(Some(&mut out[written_update..]))
        .expect("Streaming encrypt finish failed");
    assert!(written_finish.is_multiple_of(data_unit_len) || written_finish == 0);

    assert_eq!(written_update + written_finish, plaintext.len());
    assert_eq!(tweak_as_u64(&ctx.algo().tweak()), start + units as u64);
}

#[test]
fn test_aes_xts_invalid_tweak_size_too_small() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 4] = [0x01, 0x02, 0x03, 0x04]; // Too small (need 8 bytes)
    let plaintext: [u8; 32] = [0x41; 32];

    expect_xts_error(
        true,
        &key,
        &tweak,
        &plaintext,
        CryptoError::AesXtsInvalidTweakSize,
    );
}

#[test]
fn test_aes_xts_invalid_tweak_size_too_large() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 32] = [0x01; 32]; // Too large (need 8 bytes)
    let plaintext: [u8; 32] = [0x41; 32];

    expect_xts_error(
        true,
        &key,
        &tweak,
        &plaintext,
        CryptoError::AesXtsInvalidTweakSize,
    );
}

#[test]
fn test_aes_xts_tweak_overflow_encrypt() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 8] = [0xff; 8];
    let plaintext: [u8; 32] = [0x41; 32];

    expect_xts_error(
        true,
        &key,
        &tweak,
        &plaintext,
        CryptoError::AesXtsTweakOverflow,
    );
}

#[test]
fn test_aes_xts_tweak_overflow_decrypt() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 8] = [0xff; 8];
    let ciphertext: [u8; 32] = [0x41; 32];

    expect_xts_error(
        false,
        &key,
        &tweak,
        &ciphertext,
        CryptoError::AesXtsTweakOverflow,
    );
}

#[test]
fn test_aes_xts_invalid_input_size_too_small() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 8] = [0x01; 8];
    let plaintext: [u8; 8] = [0x41; 8]; // Too small (need at least 16 bytes)

    expect_xts_error(
        true,
        &key,
        &tweak,
        &plaintext,
        CryptoError::AesXtsInvalidDataUnitLen,
    );
}

#[test]
fn test_aes_xts_invalid_input_size_not_block_aligned() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 8] = [0x01; 8];
    let plaintext: [u8; 20] = [0x41; 20]; // Not a multiple of 16 bytes

    expect_xts_error(
        true,
        &key,
        &tweak,
        &plaintext,
        CryptoError::AesXtsInvalidDataUnitLen,
    );
}

#[test]
fn test_aes_xts_decrypt_invalid_input_size() {
    let key = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak: [u8; 8] = [0x01; 8];
    let ciphertext: [u8; 12] = [0x41; 12]; // Too small and not aligned

    expect_xts_error(
        false,
        &key,
        &tweak,
        &ciphertext,
        CryptoError::AesXtsInvalidDataUnitLen,
    );
}

#[test]
fn test_aes_xts_128_nist_vectors() {
    //loop through each AES_XTS_128_NIST_TEST_VECTORS
    for tv in AES_XTS_128_NIST_TEST_VECTORS.iter() {
        //import key
        let aes_xts_key = AesXtsKey::from_bytes(tv.key).expect("Failed to import key bytes");

        if tv.encrypt {
            test_xts_encrypt(
                tv.test_count_id,
                &aes_xts_key,
                tv.tweak,
                tv.plaintext,
                tv.ciphertext,
            );
        } else {
            test_xts_decrypt(
                tv.test_count_id,
                &aes_xts_key,
                tv.tweak,
                tv.ciphertext,
                tv.plaintext,
            );
        }
    }
}

#[test]
fn test_aes_xts_256_nist_vectors() {
    //loop through each AES_XTS_256_NIST_TEST_VECTORS
    for tv in AES_XTS_256_NIST_TEST_VECTORS.iter() {
        //import key
        let aes_xts_key = AesXtsKey::from_bytes(tv.key).expect("Failed to import key bytes");

        if tv.encrypt {
            test_xts_encrypt(
                tv.test_count_id,
                &aes_xts_key,
                tv.tweak,
                tv.plaintext,
                tv.ciphertext,
            );
        } else {
            test_xts_decrypt(
                tv.test_count_id,
                &aes_xts_key,
                tv.tweak,
                tv.ciphertext,
                tv.plaintext,
            );
        }
    }
}

#[test]
fn test_aes_xts_different_block_sizes() {
    // Test that encrypting 32 bytes as 2x16-byte blocks produces the same result
    // as encrypting it as 1x32-byte block
    let key_bytes = [
        0x1e, 0xa6, 0x61, 0xc5, 0x8d, 0x94, 0x3a, 0x0e, 0x48, 0x01, 0xe4, 0x2f, 0x4b, 0x09, 0x47,
        0x14, 0x9e, 0x7f, 0x9f, 0x8e, 0x3e, 0x68, 0xd0, 0xc7, 0x50, 0x52, 0x10, 0xbd, 0x31, 0x1a,
        0x0e, 0x7c,
    ];
    let tweak = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let plaintext = [
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1, 0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3,
        0x64, 0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3, 0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a,
        0x20, 0x2e,
    ];
    let expected_cipher = [
        0xc6, 0x19, 0x58, 0xae, 0x41, 0xa7, 0x4b, 0x7d, 0xd2, 0xa9, 0x33, 0xfd, 0x89, 0xd3, 0xe5,
        0x7b, 0xdf, 0x53, 0xe1, 0xa6, 0xcb, 0x6e, 0x2e, 0x4c, 0x91, 0x3c, 0x24, 0xe8, 0x5f, 0x8d,
        0x95, 0xb0,
    ];
    let key = AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-XTS key");

    // Encrypt with data block size = 16 (2 blocks)
    let mut aes_xts_16 = AesXtsAlgo::new(&tweak, 16).expect("Failed to create AES-XTS algo");
    let mut ciphertext_16 = vec![0u8; plaintext.len()];
    let encrypted_len_16 = aes_xts_16
        .encrypt(&key, &plaintext, Some(&mut ciphertext_16))
        .expect("Encryption with block size 16 failed");

    assert_eq!(
        ciphertext_16, expected_cipher,
        "Ciphertext mismatch for block size 16"
    );
    assert_eq!(encrypted_len_16, plaintext.len());

    // Encrypt with data block size = 32 (1 block)
    let mut aes_xts_32 = AesXtsAlgo::new(&tweak, 32).expect("Failed to create AES-XTS algo");
    let mut ciphertext_32 = vec![0u8; plaintext.len()];
    let encrypted_len_32 = aes_xts_32
        .encrypt(&key, &plaintext, Some(&mut ciphertext_32))
        .expect("Encryption with block size 32 failed");

    assert_eq!(encrypted_len_32, plaintext.len());

    // Both encrypted outputs should not match(sector size affects tweak calculation)
    assert_ne!(
        ciphertext_16, ciphertext_32,
        "Ciphertext mismatch between block size 16 and 32\nBlock size 16: {:02x?}\nBlock size 32: {:02x?}",
        ciphertext_16, ciphertext_32
    );
}

#[test]
fn test_aes_xts_streaming_encrypt_decrypt() {
    // Test streaming encryption and decryption with AES-128-XTS
    let key_bytes = [
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let tweak = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Create 64 bytes of plaintext (4 blocks of 16 bytes each)
    let plaintext = [
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1, 0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3,
        0x64, 0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3, 0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a,
        0x20, 0x2e, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10,
    ];

    let key = AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-XTS key");

    // Test with data_unit_len = 32 bytes (2 data units total)
    let data_unit_len = 32;

    // Streaming encryption using helper
    let ciphertext_streaming = test_xts_streaming_encrypt(
        &key,
        &tweak,
        &plaintext,
        data_unit_len,
        &[32, 32], // Two 32-byte chunks
    );

    // Compare with single-shot encryption (create fresh key to avoid handle reuse)
    let key_single =
        AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-XTS key for single-shot");
    let mut aes_xts_single =
        AesXtsAlgo::new(&tweak, data_unit_len).expect("Failed to create AES-XTS algo");
    let mut ciphertext_single = vec![0u8; plaintext.len()];
    let encrypted_single = aes_xts_single
        .encrypt(&key_single, &plaintext, Some(&mut ciphertext_single))
        .expect("Single-shot encryption failed");

    assert_eq!(encrypted_single, plaintext.len());
    assert_eq!(
        ciphertext_streaming, ciphertext_single,
        "Streaming and single-shot encryption results differ\nStreaming: {:02x?}\nSingle:   {:02x?}",
        ciphertext_streaming, ciphertext_single
    );

    // Streaming decryption using helper (create fresh key to avoid handle reuse)
    let key_decrypt =
        AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-XTS key for decryption");
    let plaintext_streaming = test_xts_streaming_decrypt(
        &key_decrypt,
        &tweak,
        &ciphertext_streaming,
        data_unit_len,
        &[32, 32], // Two 32-byte chunks
    );

    assert_eq!(
        &plaintext_streaming[..],
        &plaintext,
        "Streaming decryption failed to recover original plaintext\nExpected: {:02x?}\nActual:   {:02x?}",
        plaintext,
        &plaintext_streaming[..]
    );

    println!(" AES-XTS streaming encryption/decryption test passed");
}

#[test]
fn test_aes_xts_streaming_non_boundary() {
    // Streaming update() must be called with a multiple of `dul`; non-boundary chunks are errors.
    let key_bytes = [
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0x22, 0x22, 0x22, 0x22, 0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let tweak = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    // Create 96 bytes of plaintext (6 blocks of 16 bytes, or 3 data units of 32 bytes)
    let plaintext = [
        0x2e, 0xed, 0xea, 0x52, 0xcd, 0x82, 0x15, 0xe1, 0xac, 0xc6, 0x47, 0xe8, 0x10, 0xbb, 0xc3,
        0x64, 0x2e, 0x87, 0x28, 0x7f, 0x8d, 0x2e, 0x57, 0xe3, 0x6c, 0x0a, 0x24, 0xfb, 0xc1, 0x2a,
        0x20, 0x2e, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    let data_unit_len = 32;

    for &bad_len in &[20usize, 40usize, 36usize] {
        //crate key
        let key = AesXtsKey::from_bytes(&key_bytes).expect("Failed to create AES-XTS key");
        // Encrypt context: reject non-multiple-of-dul sizes.
        let algo_enc =
            AesXtsAlgo::new(&tweak, data_unit_len).expect("Failed to create AES-XTS algo");
        let mut enc_ctx = algo_enc
            .encrypt_init(key.clone())
            .expect("Failed to initialize encryption context");
        let mut out = vec![0u8; bad_len];

        let err = enc_ctx
            .update(&plaintext[..bad_len], Some(&mut out))
            .expect_err("Expected update() to reject non-boundary chunk");
        assert_eq!(err, CryptoError::AesXtsInvalidInputSize);

        // Decrypt context: same rule.
        let algo_dec =
            AesXtsAlgo::new(&tweak, data_unit_len).expect("Failed to create AES-XTS algo");
        let mut dec_ctx = algo_dec
            .decrypt_init(key.clone())
            .expect("Failed to initialize decryption context");
        let mut out = vec![0u8; bad_len];
        let err = dec_ctx
            .update(&plaintext[..bad_len], Some(&mut out))
            .expect_err("Expected update() to reject non-boundary chunk");
        assert_eq!(err, CryptoError::AesXtsInvalidInputSize);
    }
}

#[test]
fn test_aes_xts_identical_keys() {
    // Test that creating an AES-XTS key with identical halves fails
    let key_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0e, 0x0f,
    ];

    let result = AesXtsKey::from_bytes(&key_bytes)
        .err()
        .expect("Expected error for identical key halves");
    assert_eq!(
        result,
        CryptoError::AesXtsInvalidKey,
        "Expected AesXtsInvalidKey error"
    );
}
