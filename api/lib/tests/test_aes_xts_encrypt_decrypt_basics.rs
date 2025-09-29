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
fn test_aes_xts_encrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let data = generate_random_vector(256);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_decrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_encrypt_invalid_keyhandle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        //first is invalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &priv_key_handle1,
            &aes_key2_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //second is invalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &priv_key_handle2,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //both invalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &priv_key_handle1,
            &priv_key_handle2,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //both valid
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
fn test_aes_xts_decrypt_invalid_keyhandle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        //first keyinvalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &priv_key_handle1,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //second keyinvalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &priv_key_handle2,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //both keyinvalid
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &priv_key_handle1,
            &priv_key_handle2,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );

        assert!(result.is_err(), "result {:?}", result);

        //both valid
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
fn test_aes_xts_decrypt_with_nonmatching_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key3_handle = result.unwrap();

        //decode succeeded, but decrpyted_data not equal to data
        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key3_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_xts_encrypt_decrypt_different_keyavailability() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
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
        assert!(result.is_err(), "result {:?}", result); // The Device Should Fail This Command

        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            data.len(),
            tweak,
            data.clone(),
        );
        assert!(decrypted_result.is_err()); // The Device Should Fail This Command

        //key availiblity differnt, swap for decrpyt
        //decrypted data not equal to data
        let decrypted_result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key2_handle,
            &aes_key1_handle,
            data.len(),
            tweak,
            data.clone(),
        );
        assert!(decrypted_result.is_err()); // The Device Should Fail This Command
        let result = app_session.delete_key(&aes_key2_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_encrypt_deleted_keyhandles() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let result = app_session.delete_key(&aes_key1_handle);
        assert!(result.is_ok(), "result {:?}", result);

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
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key2_handle,
            &aes_key1_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_decrypt_deleted_keyhandles() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let result = app_session.delete_key(&aes_key1_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key1_handle,
            &aes_key2_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Decrypt,
            &aes_key2_handle,
            &aes_key1_handle,
            encrypted_data.data.len(),
            tweak,
            encrypted_data.data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_xts_encrypt_decrypt_aes_nobulk() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::AesXtsBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key2_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::Aes128,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_nonbulk_key1_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_nonbulk_key2_handle = result.unwrap();

        let result = app_session.aes_generate(
            AesKeySize::Aes192,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_nonbulk_key3_handle = result.unwrap();

        let data = generate_random_vector(1024);
        let tweak: [u8; 16usize] = [0x4; 16usize];
        let data_len = data.len();

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_key1_handle,
            &aes_nonbulk_key1_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_nonbulk_key2_handle,
            &aes_key1_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.aes_xts_encrypt_decrypt(
            AesMode::Encrypt,
            &aes_nonbulk_key1_handle,
            &aes_nonbulk_key3_handle,
            data_len, // data unit length == buffer length
            tweak,
            data.clone(),
        );
        assert!(result.is_err(), "result {:?}", result);

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
