// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::generate_random_vector;
use crate::common::rsa_unwrap_from_wrap_data;
use crate::common::OAEP_PADDING_BUFFING_LEN;
use crate::common::RSA_2K_DATA_SIZE_LIMIT;
use crate::common::RSA_3K_DATA_SIZE_LIMIT;
use crate::common::RSA_4K_DATA_SIZE_LIMIT;
use crate::common::*;

#[test]
fn test_rsa_encrypt_decrypt_multiple_times_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
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

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();
        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let message = generate_random_vector(8);

        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
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

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_2k_crt_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivateCrt,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(message, encrypted_data);

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_2k_encrypt_decrypt_with_rsa_unwrap_different_hash() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_2k_tampered_data_crypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
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
        tampered_data[0] = tampered_data[0].wrapping_add(1);

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

#[test]
fn test_rsa_2k_encrypt_decrypt_with_rsa_unwrap_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_2K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        //

        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result.clone().unwrap_err(), HsmError::RsaEncryptFailed);

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_2K_DATA_SIZE_LIMIT + 1);
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);
        // Encrypt using pub_key in wrapped_key_handle

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
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

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_3k_crt_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivateCrt,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(message, encrypted_data);

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_3k_encrypt_decrypt_with_rsa_unwrap_different_hash() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_3k_tampered_data_crypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
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
        tampered_data[0] = tampered_data[0].wrapping_add(1);

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

#[test]
fn test_rsa_3k_encrypt_decrypt_with_rsa_unwrap_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_3K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);
        // Encrypt using pub_key in wrapped_key_handle

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_4k_crt_encrypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivateCrt,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(message, encrypted_data);

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_4k_encrypt_decrypt_with_rsa_unwrap_different_hash() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_4k_tampered_data_crypt_decrypt_with_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
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
        tampered_data[0] = tampered_data[0].wrapping_add(1);

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

#[test]
fn test_rsa_4k_encrypt_decrypt_with_rsa_unwrap_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Create encrypted data large than rsa can hadle
        let data = generate_random_vector(RSA_4K_DATA_SIZE_LIMIT - OAEP_PADDING_BUFFING_LEN + 1);
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
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
            &wrapped_key_handle,
            encrypted_data.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.len(), data.len());
        assert_eq!(decrypted_data, data);
        // Encrypt using pub_key in wrapped_key_handle

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
