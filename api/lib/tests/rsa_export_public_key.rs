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
fn test_rsa_2k_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
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

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_RSA_2K_PUBLIC_KEY.to_vec());
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
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

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_RSA_3K_PUBLIC_KEY.to_vec());
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
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

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_RSA_4K_PUBLIC_KEY.to_vec());
        }
    });
}
