// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "testhooks")]
use mcr_api::*;
#[cfg(feature = "testhooks")]
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::*;

/// test_aes_gcm_encrypt_decrypt
/// Exercise basic fast path aes gcm
/// encryption and decryption operations
/// Allocate a buffer 16k long and encrypt
/// it. Then decrypt it and verify that the
/// decrypted buffer is the same as the original
/// buffer
#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_encrypt_decrypt_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_tampered_data_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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

        let mut tampered_data = encrypted_data.data.clone();
        tampered_data[0] = tampered_data[0].wrapping_add(0x1);

        let tag = encrypted_data.tag;

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            iv,
            Some(aad.clone()),
            tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_encrypt_decrypt_multi_times_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_encrypt_data_size_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        //size of multiple of 16s
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

        //size 0
        let data = generate_random_vector(0);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.clone()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let data = generate_random_vector(1);

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

        //large size
        let data = generate_random_vector(32768);

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

        //size is odd number
        let data = generate_random_vector(2039);
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

        //not multiple of 16s
        let data = generate_random_vector(24);

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
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_decrypt_data_size_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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

        let data_to_decrypt = encrypted_data.data;
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 255;
        tampered_data.truncate(new_length);

        //decrypt szie as is 64
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            iv,
            Some(aad.clone()),
            tag,
        );

        assert!(result.is_err(), "result {:?}", result);

        //  size 0;
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 0;
        tampered_data.truncate(new_length);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            iv,
            Some(aad.clone()),
            tag,
        );

        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let mut tampered_data = data_to_decrypt.clone();
        let new_length = 1;
        tampered_data.truncate(new_length);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            iv,
            Some(aad.clone()),
            tag,
        );

        assert!(result.is_err(), "result {:?}", result);

        //large size
        let mut tampered_data = data_to_decrypt.clone();
        let data = generate_random_vector(32768 - tampered_data.len());
        let additional_data: &[u8] = &data;
        tampered_data.extend_from_slice(additional_data);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            tampered_data,
            iv,
            Some(aad.clone()),
            tag,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_invalid_or_mismatched_aad() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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

        //encrypt aad is None

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

        //tampered
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

        // Modify one byte of the aad
        let mut tampered_aad = aad.clone();
        tampered_aad[0] = tampered_aad[0].wrapping_add(0x1);

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(tampered_aad),
            tag,
        );
        assert!(result.is_err(), "result {:?}", result);

        //decryped aad is None
        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            None,
            tag,
        );
        assert!(result.is_err(), "result {:?}", result);

        let data = generate_random_vector(256);
        let iv = [0x3u8; 12];

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

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            None,
            tag,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);
    });
}

/// test to verify that decryption
/// fails when the iv that is used with
/// encryption is not the same as used with
/// decryption, the decrypted buffer should not
/// be equal to the encrypted buffer
#[test]
#[cfg(feature = "testhooks")]
fn test_aes_gcm_mismatched_iv_hardcodedkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let aes_key = generate_aes(KeyType::AesGcmBulk256Unapproved);
        let result = app_session.import_key(
            aes_key.to_vec(),
            KeyClass::AesGcmBulkUnapproved,
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

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.clone()),
            tag,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}
