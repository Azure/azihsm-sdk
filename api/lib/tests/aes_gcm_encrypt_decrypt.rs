// Copyright (C) Microsoft Corporation. All rights reserved.

// Test code for Fast path aes gcm and xts encryption and decryption
// flows
// Applicable to device and mock

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

/// test_aes_gcm_encrypt_decrypt
/// Exercise basic fast path aes gcm
/// encryption and decryption operations
/// Allocate a buffer 16k long and encrypt
/// it. Then decrypt it and verify that the
/// decrypted buffer is the same as the original
/// buffer
#[test]
fn test_aes_gcm_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = vec![1; 16384];
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
        let tag = encrypted_data.tag;

        let decrypted_result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            tag,
        );
        assert!(decrypted_result.is_ok());
        let decrypted_data = decrypted_result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);
    });
}

///test_aes_gcm_encrypt_decrypt_zero_length
/// Test fast path AES GCM encryption with zero length
/// buffer. This should fail
#[test]
fn test_aes_gcm_zero_length() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        // allocate a buffer of 0 length
        let data = Vec::new();
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

///test_aes_gcm_corrupt
/// Encrypt a clear text buffer
/// Then modify one byte of the encrypted
/// buffer and then decrypt it
/// Verify that the decryption process fails
/// Notes:- If decryption is done using the same tag
/// that was generated in encryption and the ciphertext
/// is modified, the AES GCM algorithm will fail the
/// decryption
#[test]
fn test_aes_gcm_corrupt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = vec![1; 16384];
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
        let mut encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
        encrypted_data.data[9] = encrypted_data.data[9].wrapping_add(1);
        let tag = encrypted_data.tag;

        let decrypted_result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            tag,
        );
        assert!(decrypted_result.is_err());
    });
}

/// test for an invalid key
///
#[test]
fn test_aes_invalid_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
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

        let data = vec![1; 16384];
        let aad = [0x4; 32usize];
        let iv = [0x3u8; 12];

        // TBD. I have to write a separate function called decrypt_invalid_key
        // in app_session class because the key.id() accessor function or the id
        // field is private. If the id field is made public, there will be no need
        // for this accessor function
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.to_vec()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_err(), "result {:?}", result);

        /* do cleanup so that the next test can run */
    });
}

/// test to verify that decryption
/// fails when the iv that is used with
/// encryption is not the same as used with
/// decryption, the decrypted buffer should not
/// be equal to the encrypted buffer
#[test]
fn test_aes_gcm_mismatched_iv() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let data = vec![1; 16384];
        let aad = [0x4; 32usize];
        let mut iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            None,
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
        let tag = encrypted_data.tag;

        // Modify one byte of the iv
        iv[0] = 0x4;

        let decrypted_result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.to_vec()),
            tag,
        );
        assert!(decrypted_result.is_err());
    });
}
