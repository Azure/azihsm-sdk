// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_attest_ecc_key_eccgen() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
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
    });
}

#[test]
fn test_attest_ecc_key_unwrappingkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Ecc384Private,
            DigestKind::Sha1,
            KeyUsage::Derive,
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
#[cfg(feature = "testhooks")]
fn test_attest_ecc_key_importkey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            let result = app_session.import_key(
                TEST_ECC_521_PRIVATE_KEY.to_vec(),
                KeyClass::Ecc,
                None,
                KeyProperties {
                    key_usage: KeyUsage::Derive,
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
