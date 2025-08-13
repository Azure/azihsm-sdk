// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aesgen_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aesgen_non_encrypt_decrypt_keytype() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aesgen_with_name() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            Some(0x234),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aesgen_per_app() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes192,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );

        assert!(result.is_ok(), "result {:?}", result);

        let aes_key_handle = result.unwrap();

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_aes_encrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

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

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_decrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

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

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_encrypt_invalid_keyhandle() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_encrypt_decrypt(
            &priv_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 16],
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_decrypt_with_mew_handle() {
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

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle1 = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle1,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_ne!(decrypted_data.data, data);

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

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle1 = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle1,
            AesMode::Decrypt,
            encrypted_data.data,
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
fn test_aes_decrpty_with_handle_signverify_type() {
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

        let result = app_session.aes_encrypt_decrypt(
            &priv_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_encrypt_with_aesbulk256() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
    });
}

#[test]
fn test_aes_gcm_encrypt_after_session_close() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_gcm_decrypt_after_session_close() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
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
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            encrypted_data.tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_gcm_encrypt_with_aes256() {
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
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_gcm_encrypt_with_aes128() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_gcm_encrypt_with_aes192() {
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
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_aes_encrypt_with_gcm_decrypt() {
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

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
        //
    });
}

#[test]
fn test_gcm_encrypt_with_aes_decrypt() {
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

        let data = generate_random_vector(128);
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            [0x3; 12],
            Some([0x4; 32].to_vec()),
            None,
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
