// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_unmask_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        // Skip this test if device is not virtual device
        // Remove after firmware supports unmasking key
        if device.get_device_info().kind != DeviceKind::Virtual {
            println!("Skipping test_unmask_key: not a virtual device");
            return;
        }

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
        let mut aes_key_handle = result.unwrap();

        // Unmask the key
        let result = app_session.unmask_key_from_handle(&mut aes_key_handle);

        assert!(result.is_ok(), "result {:?}", result);
    });
}

// Check if AES generate returns masked key
#[test]
fn test_aes_cbc_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        // Skip this test if device is not virtual device
        // Remove after firmware supports unmasking key
        if device.get_device_info().kind != DeviceKind::Virtual {
            println!("Skipping test_unmask_key: not a virtual device");
            return;
        }

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
        assert!(aes_key_handle.masked_key().is_some());

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

// Generate AES key, unmask a new key, delete the original
// Then open the unmasked key using key tag.
#[test]
fn test_unmask_named_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        // Skip this test if device is not virtual device
        // Remove after firmware supports unmasking key
        if device.get_device_info().kind != DeviceKind::Virtual {
            println!("Skipping test_unmask_key: not a virtual device");
            return;
        }

        let app_session = common_open_app_session(device);

        let key_tag = 0x4321;

        // Generate AES key
        // Get its masked key
        // Then delete original key
        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();
        assert!(aes_key_handle.masked_key().is_some());

        let blob_masked_key = aes_key_handle.masked_key().unwrap().to_vec();

        // Unmask the key before deleting it
        // This should fail because named key can't have same tag
        {
            let result = app_session.unmask_key(&blob_masked_key);
            assert!(
                result.is_err(),
                "Should fail because key tag needs to be unique"
            );
        }

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "Failed to delete key: {:?}", result);
        drop(aes_key_handle);

        // Unmask the key
        let result = app_session.unmask_key(&blob_masked_key);
        assert!(result.is_ok(), "Failed to unmask key: {:?}", result);
        let unmasked_key_handle = result.unwrap();

        // Verify the unmasked key properties
        assert_eq!(unmasked_key_handle.kind(), KeyType::Aes256);
        assert!(unmasked_key_handle.masked_key().is_some());

        // Drop handle so we can reopen it using key tag
        drop(unmasked_key_handle);

        // 5. Open a Key handle by using tag
        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "Failed to open key by tag: {:?}", result);
        let reopened_key_handle = result.unwrap();

        assert_eq!(reopened_key_handle.kind(), KeyType::Aes256);
        // KeyHandle returned from open_key doesn't contain masked key blob
        assert!(reopened_key_handle.masked_key().is_none());
    });
}
