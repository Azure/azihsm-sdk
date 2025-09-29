// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use azihsmengine::common::rsa_key::RsaKeyData;
use azihsmengine::pkey::rsa::callback::rsa_decrypt_cb;
use azihsmengine::pkey::rsa::callback::rsa_encrypt_cb;
use azihsmengine::pkey::rsa::callback::rsa_encrypt_decrypt_init_cb;
use common::import_key_wrapped;
use common::TEST_RSA_2K_PRIVATE_KEY;
use common::TEST_RSA_3K_PRIVATE_KEY;
use common::TEST_RSA_4K_PRIVATE_KEY;
use mcr_api_resilient::DigestKind;
use mcr_api_resilient::KeyUsage;
use openssl_rust::safeapi::rsa::RsaKey;

#[test]
fn test_encrypt_decrypt_2k_key() {
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, None, false);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha256), false);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha384), false);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha512), false);
}

#[test]
fn test_encrypt_decrypt_2k_key_tampered_ciphertext() {
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, None, true);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha256), true);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha384), true);
    test_encrypt(&TEST_RSA_2K_PRIVATE_KEY, Some(DigestKind::Sha512), true);
}

#[test]
fn test_encrypt_decrypt_2k_key_wrong_key_usage() {
    test_encrypt_wrong_key_usage(&TEST_RSA_2K_PRIVATE_KEY);
}

#[test]
fn test_encrypt_decrypt_3k_key() {
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, None, false);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha256), false);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha384), false);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha512), false);
}

#[test]
fn test_encrypt_decrypt_3k_key_tampered_ciphertext() {
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, None, true);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha256), true);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha384), true);
    test_encrypt(&TEST_RSA_3K_PRIVATE_KEY, Some(DigestKind::Sha512), true);
}

#[test]
fn test_encrypt_decrypt_3k_key_wrong_key_usage() {
    test_encrypt_wrong_key_usage(&TEST_RSA_3K_PRIVATE_KEY);
}

#[test]
fn test_encrypt_decrypt_4k_key() {
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, None, false);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha256), false);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha384), false);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha512), false);
}

#[test]
fn test_encrypt_decrypt_4k_key_tampered_ciphertext() {
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, None, true);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha256), true);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha384), true);
    test_encrypt(&TEST_RSA_4K_PRIVATE_KEY, Some(DigestKind::Sha512), true);
}

#[test]
fn test_encrypt_decrypt_4k_key_wrong_key_usage() {
    test_encrypt_wrong_key_usage(&TEST_RSA_4K_PRIVATE_KEY);
}

fn test_encrypt(key: &[u8], hash_type: Option<DigestKind>, tamper_encrypt: bool) {
    let ctx = import_key_wrapped(key, KeyUsage::EncryptDecrypt);
    let rsa: RsaKey<RsaKeyData> = ctx.rsa_from_pkey().unwrap();
    let rsa_keydata = rsa.get_data().unwrap().unwrap();

    rsa_keydata.set_hash_type(hash_type);

    rsa_encrypt_decrypt_init_cb(ctx.as_mut_ptr()).unwrap();

    let test_data = [0xaa; 32];
    let mut encrypt_data = rsa_encrypt_cb(ctx.as_mut_ptr(), &test_data[..]).unwrap();

    if tamper_encrypt {
        // Flip bit
        encrypt_data[0] ^= 0x01;
        assert!(rsa_decrypt_cb(ctx.as_mut_ptr(), &encrypt_data[..]).is_err());
    } else {
        let decrypt_data = rsa_decrypt_cb(ctx.as_mut_ptr(), &encrypt_data[..]).unwrap();
        assert!(test_data[..] == decrypt_data[..]);
    }
}

fn test_encrypt_wrong_key_usage(key: &[u8]) {
    let ctx = import_key_wrapped(key, KeyUsage::SignVerify);

    rsa_encrypt_decrypt_init_cb(ctx.as_mut_ptr()).unwrap();

    let test_data = [0xaa; 32];

    // This will succeed as the public key is available
    let encrypt_data = rsa_encrypt_cb(ctx.as_mut_ptr(), &test_data[..]).unwrap();

    // This should fail as expected
    assert!(rsa_decrypt_cb(ctx.as_mut_ptr(), &encrypt_data[..]).is_err());
}
