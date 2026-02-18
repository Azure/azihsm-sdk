// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_aes_gcm_256_encrypt_decrypt_no_aad() {
    // Test AES-256 GCM encryption and decryption without AAD
    // Key: 32 bytes for AES-256
    let key_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");

    // IV: 12 bytes for GCM
    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];

    // Plaintext
    let plaintext = b"Hello, AES-GCM! This is a test message for encryption.";

    // Encryption
    let mut encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let encrypted_len = encrypt_algo
        .encrypt(&key, plaintext, Some(&mut ciphertext))
        .expect("Failed to encrypt");

    assert_eq!(
        encrypted_len,
        plaintext.len(),
        "Encrypted length should match plaintext length"
    );

    // Get the authentication tag
    let tag = encrypt_algo.tag().to_vec();
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    // Decryption
    let mut decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &tag, None).expect("Failed to create decryption algo");
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = decrypt_algo
        .decrypt(&key, &ciphertext, Some(&mut decrypted))
        .expect("Failed to decrypt");

    assert_eq!(
        decrypted_len,
        plaintext.len(),
        "Decrypted length should match plaintext length"
    );
    assert_eq!(
        &decrypted[..decrypted_len],
        plaintext,
        "Decrypted text should match original plaintext"
    );
}

// add a single shot test with aad
#[test]
fn test_aes_gcm_256_encrypt_decrypt_with_aad() {
    // Test AES-256 GCM encryption and decryption with AAD
    let key_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");

    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];

    let plaintext = b"Hello, AES-GCM with AAD! This is a test message for encryption.";
    let aad = b"Additional Authenticated Data";

    // Encryption
    let mut encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, Some(aad)).expect("Failed to create encryption algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let encrypted_len = encrypt_algo
        .encrypt(&key, plaintext, Some(&mut ciphertext))
        .expect("Failed to encrypt");

    assert_eq!(
        encrypted_len,
        plaintext.len(),
        "Encrypted length should match plaintext length"
    );

    let tag = encrypt_algo.tag().to_vec();
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    // Decryption
    let mut decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &tag, Some(aad)).expect("Failed to create decryption algo");
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = decrypt_algo
        .decrypt(&key, &ciphertext, Some(&mut decrypted))
        .expect("Failed to decrypt");
    assert_eq!(
        decrypted_len,
        plaintext.len(),
        "Decrypted length should match plaintext length"
    );
    assert_eq!(
        &decrypted[..decrypted_len],
        plaintext,
        "Decrypted text should match original plaintext"
    );
}

#[test]
fn test_aes_gcm_256_streaming_encrypt_decrypt_no_aad() {
    // Test AES-256 GCM streaming encryption and decryption without AAD
    let key_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");

    let iv = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];

    let plaintext =
        b"Streaming encryption test with multiple chunks of data to process incrementally.";

    // Streaming encryption
    let encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut encrypt_ctx = encrypt_algo
        .encrypt_init(key.clone())
        .expect("Failed to initialize encryption context");

    let mut ciphertext = Vec::new();

    // Process in chunks
    let chunk_size = 20;
    for chunk in plaintext.chunks(chunk_size) {
        let mut output = vec![0u8; chunk.len()];
        let written = encrypt_ctx
            .update(chunk, Some(&mut output))
            .expect("Failed to update encryption");
        ciphertext.extend_from_slice(&output[..written]);
    }

    // Finalize encryption
    let mut final_output = vec![0u8; 16];
    let final_written = encrypt_ctx
        .finish(Some(&mut final_output))
        .expect("Failed to finalize encryption");
    ciphertext.extend_from_slice(&final_output[..final_written]);

    // Get the tag
    let tag = encrypt_ctx.algo().tag().to_vec();
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");

    // Streaming decryption
    let decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &tag, None).expect("Failed to create decryption algo");
    let mut decrypt_ctx = decrypt_algo
        .decrypt_init(key)
        .expect("Failed to initialize decryption context");

    let mut decrypted = Vec::new();

    // Process in chunks
    for chunk in ciphertext.chunks(chunk_size) {
        let mut output = vec![0u8; chunk.len()];
        let written = decrypt_ctx
            .update(chunk, Some(&mut output))
            .expect("Failed to update decryption");
        decrypted.extend_from_slice(&output[..written]);
    }

    // Finalize decryption
    let mut final_output = vec![0u8; 16];
    let final_written = decrypt_ctx
        .finish(Some(&mut final_output))
        .expect("Failed to finalize decryption");
    decrypted.extend_from_slice(&final_output[..final_written]);

    assert_eq!(
        decrypted, plaintext,
        "Decrypted text should match original plaintext"
    );
}

#[test]
fn test_aes_gcm_256_tag_verification_fails() {
    // Test that decryption fails with incorrect tag
    let key_bytes = [0x42; 32];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");
    let iv = [0x11; 12];
    let plaintext = b"Secret message";

    // Encrypt
    let mut encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    encrypt_algo
        .encrypt(&key, plaintext, Some(&mut ciphertext))
        .expect("Failed to encrypt");

    let _correct_tag = encrypt_algo.tag().to_vec();

    // Try to decrypt with wrong tag
    let wrong_tag = [0xFF; 16];
    let mut decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &wrong_tag, None).expect("Failed to create decryption algo");
    let mut decrypted = vec![0u8; ciphertext.len()];
    let result = decrypt_algo.decrypt(&key, &ciphertext, Some(&mut decrypted));

    assert!(result.is_err(), "Decryption should fail with incorrect tag");
}

#[test]
fn test_aes_gcm_256_empty_plaintext() {
    // Test encryption and decryption of empty data
    let key_bytes = [0x55; 32];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");
    let iv = [0x22; 12];
    let plaintext = b"";

    // Encrypt
    let mut encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let encrypted_len = encrypt_algo
        .encrypt(&key, plaintext, Some(&mut ciphertext))
        .expect("Failed to encrypt");

    assert_eq!(encrypted_len, 0, "Empty plaintext should produce no output");

    let tag = encrypt_algo.tag().to_vec();

    // Decrypt
    let mut decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &tag, None).expect("Failed to create decryption algo");
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = decrypt_algo
        .decrypt(&key, &ciphertext, Some(&mut decrypted))
        .expect("Failed to decrypt");

    assert_eq!(
        decrypted_len, 0,
        "Empty ciphertext should produce no output"
    );
}

#[test]
fn test_aes_gcm_256_empty_plaintext_and_aad() {
    // Test encryption and decryption with both empty plaintext and empty AAD
    let key_bytes = [0x66; 32];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");
    let iv = [0x33; 12];
    let plaintext = b"";
    let aad = b"";

    // Encrypt
    let mut encrypt_algo =
        AesGcmAlgo::for_encrypt(&iv, Some(aad)).expect("Failed to create encryption algo");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let encrypted_len = encrypt_algo
        .encrypt(&key, plaintext, Some(&mut ciphertext))
        .expect("Failed to encrypt");

    assert_eq!(encrypted_len, 0, "Empty plaintext should produce no output");

    let tag = encrypt_algo.tag().to_vec();
    println!("Tag for empty plaintext and AAD: {:02x?}", tag);
    assert_eq!(tag.len(), 16, "Tag should be 16 bytes");
    assert!(tag.iter().any(|&b| b != 0), "Tag should not be all zeros");

    // Decrypt
    let mut decrypt_algo =
        AesGcmAlgo::for_decrypt(&iv, &tag, Some(aad)).expect("Failed to create decryption algo");
    let mut decrypted = vec![0u8; ciphertext.len()];
    let decrypted_len = decrypt_algo
        .decrypt(&key, &ciphertext, Some(&mut decrypted))
        .expect("Failed to decrypt");

    assert_eq!(
        decrypted_len, 0,
        "Empty ciphertext should produce no output"
    );
}

#[test]
fn test_aes_gcm_256_streaming_vs_single_shot() {
    // Verify streaming and single-shot produce same results
    let key_bytes = [0x33; 32];
    let key = AesKey::from_bytes(&key_bytes).expect("Failed to create AES key");
    let iv = [0x44; 12];
    let plaintext = b"Test data for comparing streaming vs single-shot encryption modes.";

    // Single-shot encryption
    let mut single_shot_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut single_shot_ct = vec![0u8; plaintext.len()];
    single_shot_algo
        .encrypt(&key, plaintext, Some(&mut single_shot_ct))
        .expect("Failed to encrypt");
    let single_shot_tag = single_shot_algo.tag().to_vec();

    // Streaming encryption
    let streaming_algo =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut streaming_ctx = streaming_algo
        .encrypt_init(key.clone())
        .expect("Failed to initialize encryption context");

    let mut streaming_ct = vec![0u8; plaintext.len()];
    let written = streaming_ctx
        .update(plaintext, Some(&mut streaming_ct))
        .expect("Failed to update");

    let final_written = streaming_ctx
        .finish(Some(&mut streaming_ct[written..]))
        .expect("Failed to finalize");

    // Truncate to actual written length
    streaming_ct.truncate(written + final_written);

    let streaming_tag = streaming_ctx.algo().tag().to_vec();

    assert_eq!(
        single_shot_ct, streaming_ct,
        "Single-shot and streaming should produce same ciphertext"
    );
    assert_eq!(
        single_shot_tag, streaming_tag,
        "Single-shot and streaming should produce same tag"
    );
}

#[test]
fn test_aes_gcm_256_different_key_sizes() {
    // Test AES-128 and AES-192 as well
    let iv = [0x33; 12];
    let plaintext = b"Testing different AES key sizes";

    // AES-128
    let key_128 = AesKey::from_bytes(&[0x11; 16]).expect("Failed to create AES-128 key");
    let mut algo_128 =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ct_128 = vec![0u8; plaintext.len()];
    algo_128
        .encrypt(&key_128, plaintext, Some(&mut ct_128))
        .expect("Failed to encrypt with AES-128");
    let tag_128 = algo_128.tag().to_vec();

    let mut decrypt_algo_128 =
        AesGcmAlgo::for_decrypt(&iv, &tag_128, None).expect("Failed to create decryption algo");
    let mut pt_128 = vec![0u8; ct_128.len()];
    decrypt_algo_128
        .decrypt(&key_128, &ct_128, Some(&mut pt_128))
        .expect("Failed to decrypt with AES-128");
    assert_eq!(&pt_128[..], plaintext);

    // AES-192
    let key_192 = AesKey::from_bytes(&[0x22; 24]).expect("Failed to create AES-192 key");
    let mut algo_192 =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ct_192 = vec![0u8; plaintext.len()];
    algo_192
        .encrypt(&key_192, plaintext, Some(&mut ct_192))
        .expect("Failed to encrypt with AES-192");
    let tag_192 = algo_192.tag().to_vec();

    let mut decrypt_algo_192 =
        AesGcmAlgo::for_decrypt(&iv, &tag_192, None).expect("Failed to create decryption algo");
    let mut pt_192 = vec![0u8; ct_192.len()];
    decrypt_algo_192
        .decrypt(&key_192, &ct_192, Some(&mut pt_192))
        .expect("Failed to decrypt with AES-192");
    assert_eq!(&pt_192[..], plaintext);

    // AES-256
    let key_256 = AesKey::from_bytes(&[0x33; 32]).expect("Failed to create AES-256 key");
    let mut algo_256 =
        AesGcmAlgo::for_encrypt(&iv, None).expect("Failed to create encryption algo");
    let mut ct_256 = vec![0u8; plaintext.len()];
    algo_256
        .encrypt(&key_256, plaintext, Some(&mut ct_256))
        .expect("Failed to encrypt with AES-256");
    let tag_256 = algo_256.tag().to_vec();

    let mut decrypt_algo_256 =
        AesGcmAlgo::for_decrypt(&iv, &tag_256, None).expect("Failed to create decryption algo");
    let mut pt_256 = vec![0u8; ct_256.len()];
    decrypt_algo_256
        .decrypt(&key_256, &ct_256, Some(&mut pt_256))
        .expect("Failed to decrypt with AES-256");
    assert_eq!(&pt_256[..], plaintext);
}
