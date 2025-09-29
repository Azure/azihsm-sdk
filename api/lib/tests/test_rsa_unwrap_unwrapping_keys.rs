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
fn test_get_rsa_unwrap_pre_defined_aes_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Get handle to private wrapping key
        let wrapping_key = get_unwrapping_key(&app_session);

        let result = app_session.export_public_key(&wrapping_key);
        assert!(result.is_ok(), "result {:?}", result);
        let wrapping_key_der = result.unwrap();

        let aes_256_wrapped = wrap_data(wrapping_key_der, TEST_AES_256.as_slice());

        // Unwrap key in wrapped_blob
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Aes,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1,
        };

        let result = app_session.rsa_unwrap(
            &wrapping_key,
            aes_256_wrapped,
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt),
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Aes256);

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![
            0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF, 0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF,
        ];

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Encrypt,
            message.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);

        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(decrypted_data.data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_unwrap_pre_defined_ecc_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Get handle to private wrapping key;
        let wrapping_key = get_unwrapping_key(&app_session);

        let result = app_session.export_public_key(&wrapping_key);
        assert!(result.is_ok(), "result {:?}", result);
        let wrapping_key_der = result.unwrap();

        let ecc_256_wrapped = wrap_data(wrapping_key_der, TEST_ECC_256_PRIVATE_KEY.as_slice());

        // Unwrap key in wrapped_blob
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Ecc,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1,
        };

        let result = app_session.rsa_unwrap(
            &wrapping_key,
            ecc_256_wrapped,
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::SignVerify),
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Ecc256Private);

        let message = generate_random_vector(20);

        let result = app_session.ecc_sign(&wrapped_key_handle, message.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, message);

        let result =
            app_session.ecc_verify(&wrapped_key_handle, message.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_get_rsa_wrap_generated_rsa_2k() {
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
        assert_eq!(wrapped_key_handle.kind(), KeyType::Rsa2kPrivate);

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
fn test_get_rsa_wrap_generated_rsa_3k() {
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
        assert_eq!(wrapped_key_handle.kind(), KeyType::Rsa3kPrivate);

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
fn test_get_rsa_wrap_generated_rsa_4k() {
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
        assert_eq!(wrapped_key_handle.kind(), KeyType::Rsa4kPrivate);

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
#[cfg(feature = "testhooks")]
fn test_get_rsa_unwrap_generated_aes128() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes128,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Aes128);

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![
            0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF, 0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF,
        ];

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Encrypt,
            message.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);

        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(decrypted_data.data, message);
        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_unwrap_generated_aes192() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes192,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Aes192);

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![
            0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF, 0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF,
        ];

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Encrypt,
            message.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);

        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(decrypted_data.data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_unwrap_generated_aes256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Aes256,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Aes256);

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![
            0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF, 0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF,
        ];

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Encrypt,
            message.clone(),
            [0x1; 16],
        );

        assert!(result.is_ok(), "result {:?}", result);

        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &wrapped_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(decrypted_data.data, message);
        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_generated_ecc256_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Ecc256Private,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Ecc256Private);

        let message = generate_random_vector(20);

        let result = app_session.ecc_sign(&wrapped_key_handle, message.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, message);

        let result =
            app_session.ecc_verify(&wrapped_key_handle, message.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_generated_ecc384_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Ecc384Private,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Ecc384Private);

        let message = generate_random_vector(20);

        let result = app_session.ecc_sign(&wrapped_key_handle, message.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 96);
        assert_ne!(signature, message);

        let result =
            app_session.ecc_verify(&wrapped_key_handle, message.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_get_rsa_generated_ecc521_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Ecc521Private,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();
        assert_eq!(wrapped_key_handle.kind(), KeyType::Ecc521Private);

        let message = generate_random_vector(20);

        let result = app_session.ecc_sign(&wrapped_key_handle, message.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 132);
        assert_ne!(signature, message);

        let result =
            app_session.ecc_verify(&wrapped_key_handle, message.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
