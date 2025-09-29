// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_get_unwrapping_key() {
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

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_get_unwrapping_key_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Get handle to private wrapping key
        let result = app_session.get_unwrapping_key();
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_get_unwrapping_key_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let totalcount = 10;

        for _i in 0..totalcount {
            // Get handle to private wrapping key
            //  get tablecount
            let _wrapping_key = get_unwrapping_key(&app_session);
        }
    });
}

#[test]
fn test_delete_unwrapping_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Get handle to private wrapping key
        let wrapping_key = get_unwrapping_key(&app_session);

        // Confirm deleting wrapping key returns error
        let result = app_session.delete_key(&wrapping_key);
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(result, Err(HsmError::CannotDeleteInternalKeys));
    });
}
