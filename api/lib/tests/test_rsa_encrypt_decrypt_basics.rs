// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_encrypt_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_encrypt_invalid_key() {
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

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &aes_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_encrypt_with_key_type_signverify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 256);
        assert_ne!(data, encrypted_data);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_decrypt_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 256);
        assert_ne!(data, encrypted_data);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_decrypt_with_non_rsa_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 256);
        assert_ne!(data, encrypted_data);

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
        let result = app_session.rsa_decrypt(
            &aes_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_decrypt_invalid_data_len() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 256);
        assert_ne!(data, encrypted_data);

        let mut tampered_data = encrypted_data.clone();
        let new_length = tampered_data.len() / 2;
        tampered_data.truncate(new_length);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        //3k
        let result = app_session.import_key(
            TEST_RSA_3K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        // Create encrypted data
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 384);
        assert_ne!(data, encrypted_data);

        let mut tampered_data = encrypted_data.clone();
        let new_length = tampered_data.len() - 1;
        tampered_data.truncate(new_length);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle

        let message = generate_random_vector(8);

        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let mut tampered_data = encrypted_data.clone();

        let data = generate_random_vector(3);
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            tampered_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
