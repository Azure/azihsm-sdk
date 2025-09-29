// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "testhooks")]
#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "testhooks")]
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
#[cfg(feature = "testhooks")]
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_encrypt_decrypt_data_size() {
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

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_2K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::RsaEncryptFailed);

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_2K_DATA_SIZE_LIMIT + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::InvalidParameter);

        // Create encrypted data size 0
        let data = generate_random_vector(0);
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

        // Create encrypted data size 1
        let data = generate_random_vector(0);
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

        // Create encrypted data size just at the limit
        let data = generate_random_vector(RSA_2K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN);
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_encrypt_decrypt_multiple_times() {
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
        assert_eq!(encrypted_data.len(), RSA_2K_DATA_SIZE_LIMIT);
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

        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(data, encrypted_data);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_encrypt_decrypt() {
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_encrypt_decrypt_different_hash() {
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

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha1),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_crt_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_tampered_data_encrypt_decrypt() {
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
fn test_rsa_3k_encrypt_decrypt() {
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
        let data = generate_random_vector(16);
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_encrypt_decrypt_different_hash() {
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
        let data = generate_random_vector(100);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha384),
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
            Some(DigestKind::Sha1),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_crt_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_tampered_data_encrypt_decrypt() {
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
fn test_rsa_3k_encrypt_decrypt_data_size() {
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

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_3K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        //

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::RsaEncryptFailed);

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_3K_DATA_SIZE_LIMIT + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        //

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::InvalidParameter);

        // Create encrypted data size 0
        let data = generate_random_vector(0);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_3K_DATA_SIZE_LIMIT);
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

        // Create encrypted data size 1
        let data = generate_random_vector(0);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_3K_DATA_SIZE_LIMIT);
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

        // Create encrypted data size just at the limit
        let data = generate_random_vector(RSA_3K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_3K_DATA_SIZE_LIMIT);
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_encrypt_decrypt() {
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
        let data = generate_random_vector(446);
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_encrypt_decrypt_different_hash() {
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
        assert_eq!(encrypted_data.len(), 512);
        assert_ne!(data, encrypted_data);

        let result = app_session.rsa_decrypt(
            &priv_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha1),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_crt_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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
        assert_eq!(encrypted_data.len(), 512);
        assert_ne!(data, encrypted_data);

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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_tampered_data_encrypt_decrypt() {
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
        assert_eq!(encrypted_data.len(), 512);
        assert_ne!(data, encrypted_data);

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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_encrypt_decrypt_data_size() {
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

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_4K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        //

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::RsaEncryptFailed);

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_4K_DATA_SIZE_LIMIT + 1);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        //

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::InvalidParameter);

        // Create encrypted data size 0
        let data = generate_random_vector(0);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_4K_DATA_SIZE_LIMIT);
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

        // Create encrypted data size 1
        let data = generate_random_vector(0);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_4K_DATA_SIZE_LIMIT);
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

        // Create encrypted data size just at the limit
        let data = generate_random_vector(RSA_4K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN);
        let result = app_session.rsa_encrypt(
            &priv_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_4K_DATA_SIZE_LIMIT);
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
    });
}
