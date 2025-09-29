// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_eccgen_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_eccgen_non_signverify_keytype() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_eccgen_with_name() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            Some(123),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_eccgen_per_app() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_sign_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

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

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(20);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecc_sign_invalid_keyhandle() {
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
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(20);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_verify_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC256_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.ecc_verify(&priv_key_handle, digest, signature.clone());

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_verify_with_mew_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC256_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

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
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_verify(&priv_key_handle1, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_verify_with_handle_encrypt_type() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC256_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

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
        let priv_key_handle1 = result.unwrap();
        let result = app_session.ecc_verify(&priv_key_handle1, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc_verify_invalid_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC256_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_verify(&priv_key_handle1, digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}
