// Copyright (C) Microsoft Corporation. All rights reserved.
// Test code for Fast path aes gcm and xts encryption and decryption
// flows
// Applicable to device and mock

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

/// test_aes_xts_encrypt_decrypt
/// Exercise basic fast path aes xts
/// encryption and decryption operations
/// Allocate a buffer 16k long and encrypt
/// it. Then decrypt it and verify that the
/// decrypted buffer is the same as the original
/// buffer
#[test]
fn test_aes_xts_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

/// test_aes_xts_corrupt
/// Perform XTS encryption
/// corrupt one or more bytes of the
/// encrypted buffer and decrypt it
/// The resulting buffer must not match
/// the original buffer
#[test]
fn test_aes_xts_corrupt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = vec![1; 512];
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
        let mut encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data_len);
        assert_ne!(data, encrypted_data.data);

        /* modify byte 9.
         * Account for overflow.
         * All we need to do is to modify byte 0
         */
        encrypted_data.data[9] = encrypted_data.data[9].wrapping_add(1);

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

/// test_aes_xts_switch_keys
/// Run AES Xts encryption with
/// one set of keys
/// Then perform Aes XTS decryption
/// on the encrypted buffer but with
/// the keys switched. The resulting
/// decrypted buffer must not be the same
/// as the encrypted buffer
#[test]
fn test_aes_xts_switch_keys() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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
    });
}

/// test_aes_xts_invalid_keys
/// Run AES Xts encryption with
/// one set of keys
/// Then delete both keys
/// The run decryption. Decryption
/// should fail
#[test]
fn test_aes_xts_invalid_keys() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let result = app_session.delete_key(&aes_key1_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&aes_key2_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(decrypted_result.is_err());
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
fn test_aes_xts_invalid_tweak_value() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = vec![1; 1024 * 1024];
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
