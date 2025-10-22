// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_rsa_import_key_encrypt_decrypt() {
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

            let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
            assert!(result.is_ok(), "result {:?}", result);

            let response_report = result.unwrap();
            //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
            assert!(response_report.len() <= 834 && !response_report.is_empty());
        }
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_rsa_import_key_signverify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_RSA_3K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::SignVerify,
                    key_availability: KeyAvailability::Session,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let priv_key_handle = result.unwrap();

            let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
            assert!(result.is_ok(), "result {:?}", result);

            let response_report = result.unwrap();
            //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
            assert!(response_report.len() <= 834 && !response_report.is_empty());
        }
    });
}

#[test]
fn test_attest_rsa_unwrapping_key_signverify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
        assert!(result.is_ok(), "result {:?}", result);

        let response_report = result.unwrap();
        //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
        assert!(response_report.len() <= 834 && !response_report.is_empty());

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_attest_rsa_unwrapping_key_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::EncryptDecrypt,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.attest_key(&priv_key_handle, &[2; 128]);
        assert!(result.is_ok(), "result {:?}", result);

        let response_report = result.unwrap();
        //TAGGED_COSE_SIGN1_OBJECT_MAX_SIZE 834
        assert!(response_report.len() <= 834 && !response_report.is_empty());

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
