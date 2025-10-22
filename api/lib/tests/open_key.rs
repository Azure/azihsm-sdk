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
fn test_open_key() {
    use common::TEST_APP_CREDENTIALS;

    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Import a Session Key with key tag is not allowed
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(0x6677),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        // Import an App key with a specified tag
        let key_tag = 0x6677;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let pri_key_id = result.unwrap();

        // Attempt to import one more key with the same specified tag
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
        if let Err(err) = result {
            assert_eq!(err, HsmError::KeyTagAlreadyExists);
        }

        // Import a key with a different tag
        let key_tag2 = key_tag + 1;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag2),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let pri_key_id2 = result.unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle1 = result.unwrap();

        let result = app_session.open_key(key_tag2);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle2 = result.unwrap();

        let result = app_session.export_public_key(&pri_key_id);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_pub_key = result.unwrap();

        let result = app_session.export_public_key(&key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_key1 = result.unwrap();

        assert_eq!(exported_pub_key, exported_key1);

        let result = app_session.export_public_key(&pri_key_id2);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_pub_key2 = result.unwrap();

        let result = app_session.export_public_key(&key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_key2 = result.unwrap();

        assert_eq!(exported_pub_key2, exported_key2);

        let result = app_session.delete_key(&pri_key_id);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&pri_key_id2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_basic() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            // Import a key with a specified tag, from ecc_generate
            let key_tag = 0x7724;
            let result = app_session.ecc_generate(
                EccCurve::P256,
                Some(key_tag),
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::App,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();
            let raw_key_pub = app_session.export_public_key(&priv_key_handle).unwrap();

            let result = app_session.open_key(key_tag);
            assert!(result.is_ok(), "result {:?}", result);
            let key_handle = result.unwrap();
            let result = app_session.export_public_key(&key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let raw_key = result.unwrap();
            assert_eq!(raw_key_pub, raw_key);

            let result = app_session.delete_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }

        {
            {
                // Import a private key with a specified tag, from der
                let key_tag = 0x7723;
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
                let priv_key_handle = result.unwrap();
                let result = app_session.export_public_key(&priv_key_handle);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key = result.unwrap();
                assert_eq!(raw_key, TEST_RSA_2K_PUBLIC_KEY.to_vec());

                let result = app_session.open_key(key_tag);
                assert!(result.is_ok(), "result {:?}", result);
                let key_handle2 = result.unwrap();
                let result = app_session.export_public_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key2 = result.unwrap();
                assert_eq!(raw_key, raw_key2);

                let result = app_session.delete_key(&priv_key_handle);
                assert!(result.is_ok(), "result {:?}", result);
            }
        }
    });
}
