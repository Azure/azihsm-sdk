// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::TEST_RSA_2K_PRIVATE_KEY;
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_attest_rsa_key() {
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
        }
    });
}

#[test]
fn test_attest_ecc_key() {
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
    });
}

#[test]
fn test_attest_aes_key_negative() {
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

        let result = app_session.attest_key(&aes_key_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}

#[test]
fn test_attest_secret_negative() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret_handle = result.unwrap();

        let result = app_session.attest_key(&secret_handle, &[2; 128]);
        assert_eq!(result, Err(HsmError::InvalidKeyType));
    });
}
