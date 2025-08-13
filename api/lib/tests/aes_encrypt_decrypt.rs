// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aes_cbc_encrypt_decrypt() {
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

        let data = vec![1; 128];
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

        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x1; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_cbc_iv_chaining_encrypt_decrypt() {
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

        let data = vec![1; 32]; // 32 bytes buffer
        let input_iv = [0x1; 16];

        //  Encrypt the first 16 bytes
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data[0..16].to_vec(),
            input_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let first_encrypted = result.unwrap();
        let output_iv = first_encrypted.iv;

        //  Encrypt the next 16 bytes using the output IV from Step above
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data[16..32].to_vec(),
            output_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let second_encrypted = result.unwrap();

        // Combine encrypted data
        let combined_encrypted = [first_encrypted.data, second_encrypted.data].concat();

        // Decrypt the full 32 bytes in one step
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            combined_encrypted,
            input_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data.data, data);
    });
}

#[test]
fn test_aes_cbc_iv_encrypt_chaining_decrypt() {
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

        let data = vec![1; 32]; // 32 bytes buffer
        let input_iv = [0x1; 16];

        // Encrypt the full 32 bytes
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            input_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        // Decrypt the first 16 bytes
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data[0..16].to_vec(),
            input_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let first_decrypted = result.unwrap();
        let output_iv = first_decrypted.iv;

        //  Decrypt the next 16 bytes using the output IV from Step above
        let result = app_session.aes_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Decrypt,
            encrypted_data.data[16..32].to_vec(),
            output_iv,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let second_decrypted = result.unwrap();

        // Combine decrypted data
        let combined_decrypted = [first_decrypted.data, second_decrypted.data].concat();

        assert_eq!(combined_decrypted, data);
    });
}
