// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "testhooks")]
use mcr_api::*;
#[cfg(feature = "testhooks")]
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_encrypt_decrypt_oaep() {
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
        let data = vec![1; 100];
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
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data;
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_encrypt_decrypt_oaep() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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
        let data = vec![1; 100];
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

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.import_key(
            TEST_RSA_3K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data;
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_encrypt_decrypt_oaep() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
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
        let data = vec![1; 100];
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), 512);
        assert_ne!(data, encrypted_data);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);

        let mut tampered_data = encrypted_data;
        tampered_data[0] = tampered_data[0].wrapping_add(1);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            tampered_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}
