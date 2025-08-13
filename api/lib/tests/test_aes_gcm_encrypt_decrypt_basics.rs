// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aes_fpgcm_encrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_decrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            encrypted_data.tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_encrypt_invalid_keyhandle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();
        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &priv_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_decrpty_with_invalid_keyhandle() {
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
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
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
        let priv_key_handle = result.unwrap();

        let result = app_session.aes_gcm_encrypt_decrypt(
            &priv_key_handle,
            AesMode::Decrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            encrypted_data.tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_decrypt_with_nonmatching_handle() {
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
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle1 = result.unwrap();

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle1,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            encrypted_data.tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_gcm_encrypt_with_deleted_key_handle() {
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
        let aes_key_handle = result.unwrap();

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let data = generate_random_vector(256);
        let aad = generate_random_vector(32);
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.clone()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_err(), "result {:?}", result);

        /* do cleanup so that the next test can run */
    });
}

#[test]
fn test_aes_gcm_decrypt_with_deleted_key_handle() {
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
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = generate_random_vector(32);
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.clone()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
        let tag = encrypted_data.tag;

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.clone()),
            tag,
        );
        assert!(result.is_err(), "result {:?}", result);

        /* do cleanup so that the next test can run */
    });
}

#[test]
fn test_aes_gcm_encrypt_decrypt_keyavailability_app() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesBulk256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = generate_random_vector(32);
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.clone()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
        let tag = encrypted_data.tag;

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.clone()),
            tag,
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
fn test_aes_fpgcm_encrypt_with_aes256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(128);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_encrypt_with_aes128() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes128,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_encrypt_with_aes192() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes192,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_encrypt_fpgcm_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes192,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
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

        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];
        let tag = [0x1; 16];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            Some(tag),
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_fpgcm_encrypt_aes_decrypt() {
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
        let aes_key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
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
        assert!(result.is_err(), "result {:?}", result);
    });
}
