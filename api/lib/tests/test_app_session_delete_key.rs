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
fn test_delete_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import an App key with a specified tag

        {
            let key_tag = 0x6677;
            let result = app_session.import_key(
                TEST_RSA_2K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                Some(key_tag),
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::App,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let _pri_key_id = result.unwrap();

            let result = app_session.open_key(key_tag);
            assert!(result.is_ok(), "result {:?}", result);
            let key_handle = result.unwrap();

            let result = app_session.delete_key(&key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_delete_key_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x6677;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle = result.unwrap();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_err(), "result {:?}", result);

        //clean  up
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_delete_key_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x6877;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        //use clone becuae HsmKeyHandle doesnt implement copy
        let key_handle = result.unwrap().clone();
        let key_handle1 = &key_handle;

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(key_handle1);
        assert!(result.is_err(), "result {:?}", result);
    });
}
