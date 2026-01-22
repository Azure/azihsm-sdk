// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

const AES_XTS_TEST_KEY_BIT_SIZE: usize = 512;
const AES_XTS_TEST_TWEAK_SIZE: usize = 16; // 128 bits

fn aes_xts_generate_key(session: &HsmSession) -> HsmResult<HsmAesXtsKey> {
    let props = HsmKeyPropsBuilder::default()
        .class(HsmKeyClass::Secret)
        .key_kind(HsmKeyKind::AesXts)
        .bits(512)
        .can_encrypt(true)
        .can_decrypt(true)
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
    assert_eq!(key.can_encrypt(), true, "Key should support encryption");
    assert_eq!(key.can_decrypt(), true, "Key should support decryption");
    Ok(key)
}

#[session_test]
fn aes_xts_encrypt_decrypt_test(session: HsmSession) {
    let key = aes_xts_generate_key(&session).expect("Failed to generate XTS key ");

    let tweak: [u8; AES_XTS_TEST_TWEAK_SIZE] = [0x00; AES_XTS_TEST_TWEAK_SIZE];
    let dul: usize = 512; // Data Unit Length

    let mut algo = HsmAesXtsAlgo::new(&tweak, dul).expect("Failed to create AES XTS algo");

    let plaintext: Vec<u8> = vec![0x11u8; 2048]; // 2048 bytes of test data
    let mut ciphertext = vec![0u8; plaintext.len()];

    // Encrypt
    let enc_size = algo
        .encrypt(&key, &plaintext, Some(&mut ciphertext))
        .expect("Encryption failed");
    assert_eq!(enc_size, plaintext.len(), "Encrypted size mismatch");

    // Decrypt
    let dec_size = algo
        .decrypt(&key, &ciphertext, None)
        .expect("Decryption failed");
    assert_eq!(dec_size, plaintext.len(), "Decrypted size mismatch");
    //allocate buffer and perform decryption
    let mut decrypted_text = vec![0u8; dec_size];

    // call decrypt with buffer
    let dec_size = algo
        .decrypt(&key, &ciphertext, Some(&mut decrypted_text))
        .expect("Decryption with buffer failed");
    // Verify
    assert_eq!(
        plaintext, decrypted_text,
        "Decrypted text does not match the original plaintext"
    );
}
