// Copyright (C) Microsoft Corporation. All rights reserved.
// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_export_pub_key_when_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        {
            // Import an App key with a specified tag
            let key_tag = 0x6887;
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
            let pri_key_handle = result.unwrap();

            let result = app_session.close_session();
            assert!(result.is_ok(), "result {:?}", result);

            let result = app_session.export_public_key(&pri_key_handle);
            assert!(result.is_err(), "result {:?}", result);
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_export_pub_key_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
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
            let pri_key_handle = result.unwrap();
            let pri_key_handle1 = pri_key_handle.clone();

            let result = app_session.export_public_key(&pri_key_handle);
            assert!(result.is_ok(), "result {:?}", result);

            let result = app_session.export_public_key(&pri_key_handle1);
            assert!(result.is_ok(), "result {:?}", result);

            let result = app_session.delete_key(&pri_key_handle1);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

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

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_export_after_multiple_import() {
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
            let priv_key_handle_4k = result.unwrap();

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
            let priv_key_handle_3k = result.unwrap();

            let result = app_session.export_public_key(&priv_key_handle_4k);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_RSA_4K_PUBLIC_KEY.to_vec());

            let result = app_session.export_public_key(&priv_key_handle_3k);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_RSA_3K_PUBLIC_KEY.to_vec());
        }
    });
}

#[test]
fn test_export_pub_key_aes_invalid_keytype() {
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

        let result = app_session.export_public_key(&aes_key_handle);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_export_pub_key_ecc_generated_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.export_public_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
        let _exported_pub_key = result.unwrap();
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_256_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_ECC_256_PRIVATE_KEY.to_vec(),
                KeyClass::Ecc,
                None,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_ECC_256_PUBLIC_KEY.to_vec());
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_384_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_ECC_384_PRIVATE_KEY.to_vec(),
                KeyClass::Ecc,
                None,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_ECC_384_PUBLIC_KEY.to_vec());
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_521_export_public_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_ECC_521_PRIVATE_KEY.to_vec(),
                KeyClass::Ecc,
                None,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let result = app_session.export_public_key(&priv_key_handle);
            assert!(result.is_ok(), "result {:?}", result);
            let exported_pub_key = result.unwrap();

            assert_eq!(exported_pub_key, TEST_ECC_521_PUBLIC_KEY.to_vec());
        }
    });
}
