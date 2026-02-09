// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_gen_key() {
    // Test generating a 128-bit AES CBC key
    let key = AesCbcKey::gen_key(16);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 16);

    // Test generating a 192-bit AES CBC key
    let key = AesCbcKey::gen_key(24);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 24);

    // Test generating a 256-bit AES CBC key
    let key = AesCbcKey::gen_key(32);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 32);

    // Test generating an invalid key size
    let key = AesCbcKey::gen_key(20);
    assert!(key.is_err());
    assert_eq!(key.err().unwrap(), CryptoError::AesInvalidKeySize);
}

#[test]
fn test_from_slice() {
    // Test creating a key from a valid 128-bit slice
    let key_data = vec![0u8; 16];
    let key = AesCbcKey::from_slice(&key_data);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 16);

    // Test creating a key from a valid 192-bit slice
    let key_data = vec![0u8; 24];
    let key = AesCbcKey::from_slice(&key_data);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 24);

    // Test creating a key from a valid 256-bit slice
    let key_data = vec![0u8; 32];
    let key = AesCbcKey::from_slice(&key_data);
    assert!(key.is_ok());
    assert_eq!(key.unwrap().key.size(), 32);

    // Test creating a key from an invalid slice size
    let key_data = vec![0u8; 20];
    let key = AesCbcKey::from_slice(&key_data);
    assert_eq!(key.err().unwrap(), CryptoError::AesInvalidKeySize);
}

#[test]
fn test_as_slice() {
    // Test extracting key bytes into a buffer
    let key_data = vec![1u8; 16];
    let key = AesCbcKey::from_slice(&key_data).unwrap();
    let mut buf = vec![0u8; 16];
    let result = key.key.as_slice(Some(&mut buf));
    assert!(result.is_ok());
    assert_eq!(buf, key_data);
    assert_eq!(result.unwrap(), 16);

    // Test extracting key bytes without providing a buffer
    let result = key.key.as_slice(None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 16);

    // Test extracting key bytes with insufficient buffer size
    let mut small_buf = vec![0u8; 8];
    let result = key.key.as_slice(Some(&mut small_buf));
    assert_eq!(result.err().unwrap(), CryptoError::AesBufferTooSmall);

    // Test with generated key
    let gen_key = AesCbcKey::gen_key(32).unwrap();
    let mut buf = vec![0u8; 32];
    let result = gen_key.key.as_slice(Some(&mut buf));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 32);
    assert_ne!(buf, vec![0u8; 32]);
}

// test multi step encrypt/decrypt with padding
#[test]
fn test_encrypt_decrypt_cbc_padding() {
    let key = AesCbcKey::gen_key(16).unwrap();
    let mut iv = [1u8; 16];
    let plaintext = [1u8; 48];

    let mut offset = 0;
    let mut ciphertext = vec![0u8; plaintext.len() + 16];

    // Encrypt in multiple steps
    let mut context = key
        .encrypt_decrypt_init(AesCbcMode::Encrypt, true, &iv)
        .unwrap();
    offset += context
        .encrypt_decrypt_update(&plaintext, Some(&mut ciphertext[offset..]))
        .unwrap();
    // offset += context
    //     .encrypt_decrypt_update(&plaintext[2..], Some(&mut ciphertext[offset..]))
    //     .unwrap();
    offset += context
        .encrypt_decrypt_final(Some(&mut ciphertext[offset..]))
        .unwrap();
    ciphertext.truncate(offset);

    let mut iv = [1u8; 16];
    // Decrypt in multiple steps

    let mut decrypted_text = vec![0u8; ciphertext.len()];
    let mut offset = 0;

    let mut context = key
        .encrypt_decrypt_init(AesCbcMode::Decrypt, true, &iv)
        .unwrap();
    offset += context
        .encrypt_decrypt_update(&ciphertext, Some(&mut decrypted_text[offset..]))
        .unwrap();
    // offset += context
    //     .encrypt_decrypt_update(&ciphertext[10..], Some(&mut decrypted_text[offset..]))
    //     .unwrap();
    offset += context
        .encrypt_decrypt_final(Some(&mut decrypted_text[offset..]))
        .unwrap();
    decrypted_text.truncate(offset);
    assert_eq!(&decrypted_text, &plaintext);
}
