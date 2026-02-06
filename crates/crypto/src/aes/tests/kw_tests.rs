// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn test_aes128_kw_encrypt_decrypt() {
    let key = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let ct = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_kw = AesKeyWrapAlgo::with_default_iv();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_kw, &aes_key, &pt).expect("AES KW encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_kw, &aes_key, &ct).expect("AES KW decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes192_kw_encrypt_decrypt() {
    let key = hex::decode("000102030405060708090A0B0C0D0E0F1011121314151617").unwrap();
    let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let ct = hex::decode("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_kw = AesKeyWrapAlgo::with_default_iv();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_kw, &aes_key, &pt).expect("AES KW encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_kw, &aes_key, &ct).expect("AES KW decryption failed");
    assert_eq!(actual_pt, pt);
}

#[test]
fn test_aes256_kw_encrypt_decrypt() {
    let key =
        hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F").unwrap();
    let pt = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
    let ct = hex::decode("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7").unwrap();

    let aes_key = AesKey::from_bytes(&key).expect("Failed to create AES key");
    let mut aes_kw = AesKeyWrapAlgo::with_default_iv();

    // Encrypt
    let actual_ct =
        Encrypter::encrypt_vec(&mut aes_kw, &aes_key, &pt).expect("AES KW encryption failed");
    assert_eq!(actual_ct, ct);

    // Decrypt
    let actual_pt =
        Decrypter::decrypt_vec(&mut aes_kw, &aes_key, &ct).expect("AES KW decryption failed");
    assert_eq!(actual_pt, pt);
}
