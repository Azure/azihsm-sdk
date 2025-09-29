// Copyright (C) Microsoft Corporation. All rights reserved.

// Test code for Fast path aes gcm and xts encryption and decryption
// flows
// Applicable to device and mock

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aes_xts_encrypt_decrypt_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_xts_tampered_data_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(512);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let mut tampered_data = encrypted_data.data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            tampered_data,
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_ne!(decrypted_data.data, data);
    });
}

/// test_aes_xts_invalid_tweak_value
/// Run AES Xts encryption with
/// one value for the tweak
/// Change the tweak value
/// Then do Aes Xts decryption with
/// the modified tweak value
/// The resulting cleartext buffer must not
/// match the original cleartext
#[test]
fn test_aes_xts_tampered_tweak_value_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);

        let mut tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        tweak[0] += 1;

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_xts_encrypt_decrypt_multi_times_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let data = generate_random_vector(2048);
        let tweak: [u8; 16usize] = [0x7; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_xts_encrypt_data_size_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        //size 2048 same as data len
        let data = generate_random_vector(2048);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        //size 512 allowed,  smaller than data size
        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();
        let input_len = 512;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        //size 512 , allowed,  dul large than data size
        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let input_len = 512;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 4096 allowed,  large than data size
        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let input_len = 4096;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 4096 allowed,  smaller than data size
        let data = generate_random_vector(5120);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let input_len = 4096;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 4096 large than data size
        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let input_len = 4096;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 8192 smaller than data size
        let data = generate_random_vector(256 * 1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();
        let input_len = 4096;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            input_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        //size 1024 not the same as data size, not the allowed size either
        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = 1024;

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 0
        let data = generate_random_vector(0);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let data = generate_random_vector(1);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //size <16
        let data = generate_random_vector(14);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 16
        let data = generate_random_vector(16);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        // Note: The HW doesn't support non 16 byte aligned sizes
        // Uncomment when/if it does.

        // //size > 16
        // let data = generate_random_vector(17);
        // let tweak: [u8; 16usize] = [0x4; 16usize];
        // let data_len = data.len();

        // let result = app_session.aes_xts_encrypt_decrypt(
        //     AesMode::Encrypt,
        //     &aes_key1_handle,
        //     &aes_key2_handle,
        //     data_len, // data unit length == buffer length
        //     tweak,
        //     data.clone(),
        // );
        // assert!(result.is_ok(), "result {:?}", result);
        // let encrypted_data = result.unwrap();
        // assert_eq!(encrypted_data.data.len(), data_len);
        // assert_ne!(data, encrypted_data.data);

        // //size is odd
        // let data = generate_random_vector(109);
        // let tweak: [u8; 16usize] = [0x4; 16usize];
        // let data_len = data.len();

        // let result = app_session.aes_xts_encrypt_decrypt(
        //     AesMode::Encrypt,
        //     &aes_key1_handle,
        //     &aes_key2_handle,
        //     data_len, // data unit length == buffer length
        //     tweak,
        //     data.clone(),
        // );
        // assert!(result.is_ok(), "result {:?}", result);
        // let encrypted_data = result.unwrap();
        // assert_eq!(encrypted_data.data.len(), data_len);
        // assert_ne!(data, encrypted_data.data);

        //big size
        let data = generate_random_vector(2048 * 1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);
    });
}

#[test]
fn test_aes_xts_decrypt_data_size_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        // len 512 but samller than original data,
        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            512,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        // len 512 but larger than original data,
        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            512,
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(decrypted_result.is_err());
        assert_eq!(decrypted_result.unwrap_err(), HsmError::InvalidParameter);

        // len 4096 large than origina data to encrypt
        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            4096,
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(decrypted_result.is_err());
        assert_eq!(decrypted_result.unwrap_err(), HsmError::InvalidParameter);

        // len 4096 smallerthan origina data to encrypt
        let data = generate_random_vector(8192);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            4096,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        // len 8192 smaller than origina data to encrypt
        let data = generate_random_vector(1024 * 128);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            8192,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        // len 8192, larger than original data len

        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            8192,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_err());
        assert_eq!(decrypted_result.unwrap_err(), HsmError::InvalidParameter);

        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        // len 2056, not allowed size, not the data len either
        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            2056,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_err());
        assert_eq!(decrypted_result.unwrap_err(), HsmError::InvalidParameter);

        let data_to_decrypt = encrypted_data.data;

        // Note: The HW doesn't support non 16 byte aligned sizes
        // Uncomment when/if it does.

        // decrypt size as is 255
        // let mut tampered_data = data_to_decrypt.clone();
        // let new_length = 255;
        // tampered_data.truncate(new_length);

        // let result = app_session.aes_xts_encrypt_decrypt(
        //     AesMode::Decrypt,
        //     &aes_key1_handle,
        //     &aes_key2_handle,
        //     new_length,
        //     tweak,
        //     tampered_data,
        // );
        // assert!(result.is_ok(), "result {:?}", result);
        // let decrypted_data = result.unwrap();
        // assert_ne!(decrypted_data.data.len(), data.len());
        // assert_ne!(decrypted_data.data, data);

        //size 0

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 0;
        tampered_data.truncate(new_length);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            new_length,
            tweak,
            tampered_data,
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 1

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 1;
        tampered_data.truncate(new_length);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            new_length,
            tweak,
            tampered_data,
        );
        assert!(result.is_err(), "result {:?}", result);

        //size <16

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 14;
        tampered_data.truncate(new_length);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            new_length,
            tweak,
            tampered_data,
        );
        assert!(result.is_err(), "result {:?}", result);

        //size = 16

        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 16;
        tampered_data.truncate(new_length);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            new_length,
            tweak,
            tampered_data,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_ne!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

        //large size

        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(1024 * 1024 - tampered_data.len());
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            tampered_data.len(),
            tweak,
            tampered_data,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_ne!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_xts_encrypt_mismatched_datalen_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        //data len < real size
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len - 2, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //data len > real size
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len + 1, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_decrypt_mismatched_datalen_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        //len < data size
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len() - 2,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        //len > data size
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len() + 1,
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

/// test_aes_xts_switch_keys
/// Run AES Xts encryption with
/// one set of keys
/// Then perform Aes XTS decryption
/// on the encrypted buffer but with
/// the keys switched. The resulting
/// decrypted buffer must not be the same
/// as the encrypted buffer
#[test]
fn test_aes_xts_switch_keys_rsaunwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::AesXtsBulk256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = vec![1; 1024 * 1024];
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key2_handle,
            &aes_key1_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_ne!(decrypted_data.data, data);

        let result = app_session.delete_key(&aes_key1_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key2_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
