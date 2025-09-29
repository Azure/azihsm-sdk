// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "testhooks")]
#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "testhooks")]
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
#[cfg(feature = "testhooks")]
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_after_close_session() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let mut app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        //clean  up
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let imported_key = result.unwrap();
        assert_eq!(imported_key.kind(), KeyType::Rsa3kPrivate);

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let imported_key = result.unwrap();
        assert_eq!(imported_key.kind(), KeyType::Rsa3kPrivate);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_non_rsa_imported_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_ECC_256_PRIVATE_KEY.to_vec(),
            KeyClass::Ecc,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Ecc256Private);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let imported_key = result.unwrap();
        assert_eq!(imported_key.kind(), KeyType::Rsa3kPrivate);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_mismtached_unwrap_key_type() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Ecc,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_tampered_wrapped_blob() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);

        // Use openssl to generate the wrapped blob.
        let wrapped_blob = &TEST_RSA_3K_PRIVATE_CKM_WRAPPED;
        let mut wrapped_blob_trunc = wrapped_blob.to_vec();
        wrapped_blob_trunc.truncate(wrapped_blob.len() / 2);
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1, // try sha256, sha384, sha512
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob_trunc,
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_unwrap_non_sha1() {
    api_test(common_setup, common_cleanup, |device, _path| {
        if device.get_device_info().kind == DeviceKind::Physical {
            println!("Physical device found. Test not supported on Physical device.");
            return;
        }

        let app_session = common_open_app_session(device);

        // Wrapped blob could be generated with OpenSSL instead of from AKV?

        // test hooks is needed for importing raw private keys into the MCR.
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let transfer_priv_key_handle = result.unwrap();
        assert_eq!(transfer_priv_key_handle.kind(), KeyType::Rsa2kPrivate);

        // Use openssl to generate the wrapped blob generated by sha1.
        let wrapped_blob = &TEST_RSA_3K_PRIVATE_CKM_WRAPPED;

        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha256,
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha384,
        };

        let result = app_session.rsa_unwrap(
            &transfer_priv_key_handle,
            wrapped_blob.to_vec(),
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt), // this is the actual intended key.
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}
