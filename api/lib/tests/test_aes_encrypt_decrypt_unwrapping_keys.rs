// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aes128_unwrap_key_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes128_unwrap_key_encrypt_decrypt_tampered_encrypted_data() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let mut tampered_data = encrypted_data.data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes128_unwrap_key_encrypt_decrypt_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes128_unwrap_key_encrypt_decrypt_keysize_type_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes128_unwrap_key_encrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        //size of multiple of 16s
        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size 0
        let data = generate_random_vector(0);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let data = generate_random_vector(1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024
        let data = generate_random_vector(1024);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size > 1024
        let data = generate_random_vector(2048);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let data = generate_random_vector(959);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes128_unwrap_key_decrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let data_to_decrypt = encrypted_data.data;
        //decrypt szie as is 64
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data_to_decrypt.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //  size 0;

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 0;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 1;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024

        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len());
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_ne!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        //size > 1024
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len() + 5);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(tampered_data.len() + 31);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_encrypt_decrypt_tampered_encrypted_data() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let mut tampered_data = encrypted_data.data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_encrypt_decrypt_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_encrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        //size of multiple of 16s
        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size 0
        let data = generate_random_vector(0);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let data = generate_random_vector(1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024
        let data = generate_random_vector(1024);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size > 1024
        let data = generate_random_vector(2048);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let data = generate_random_vector(959);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_decrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let data_to_decrypt = encrypted_data.data;
        //decrypt szie as is 64
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data_to_decrypt.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //  size 0;

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 0;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 1;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024

        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len());
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_ne!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        //size > 1024
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len() + 5);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(tampered_data.len() + 31);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes192_unwrap_key_encrypt_decrypt_keysize_type_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_encrypt_decrypt_tampered_encrypted_data() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let mut tampered_data = encrypted_data.data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_encrypt_decrypt_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_encrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        //size of multiple of 16s
        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size 0
        let data = generate_random_vector(0);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let data = generate_random_vector(1);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024
        let data = generate_random_vector(1024);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //size > 1024
        let data = generate_random_vector(2048);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let data = generate_random_vector(959);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_decrypt_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let data_to_decrypt = encrypted_data.data;
        //decrypt szie as is 64
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            data_to_decrypt.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        //  size 0;

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 0;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 1;
        tampered_data.truncate(new_length);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1024

        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len());
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_ne!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        //size > 1024
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 - tampered_data.len() + 5);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        //not multiple of 16s
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(tampered_data.len() + 31);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes256_unwrap_key_encrypt_decrypt_keysize_type_mismatch() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(64);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
