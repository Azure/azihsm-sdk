// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[test]
fn test_aes128_ecb_encrypt_decrypt() {
    let key = hex::decode("80000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("0EDD33D3C621E546455BD8BA1418BEC8").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes192_ecb_encrypt_decrypt() {
    let key = hex::decode("800000000000000000000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("de885dc87f5a92594082d02cc1e1b42c").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes256_ecb_encrypt_decrypt() {
    let key =
        hex::decode("8000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let pt = hex::decode("00000000000000000000000000000000").unwrap();
    let ct = hex::decode("e35a6dcb19b201a01ebcfa8aa22b5759").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_ecb = AesEcbAlgo::default();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_ecb, &aes_key, &pt).expect("AES ECB encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_ecb, &aes_key, &ct).expect("AES ECB decryption failed");
    assert_eq!(actual_pt, pt);
}
