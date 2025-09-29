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
fn test_ecc256_import_key_sign_verify() {
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

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_import_key_sign_verify_tampered_digestdata() {
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

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_import_key_sign_verify_tampered_sig() {
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

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_import_key_sign_verify_multi_times() {
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
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());

        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(32);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_import_key_sign_verify_data_size() {
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

        //size 20
        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size 0
        let digest = generate_random_vector(0);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let digest = generate_random_vector(1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC256_DATA_LEN_LIMIT -1, notallowed size
        let digest = generate_random_vector(ECC256_DATA_LEN_LIMIT - 1);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC256_DATA_LEN_LIMIT
        let digest = generate_random_vector(ECC256_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size ECC256_DATA_LEN_LIMIT +1
        let digest = generate_random_vector(ECC256_DATA_LEN_LIMIT + 1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC384_DATA_LEN_LIMIT , noy allowed size
        let digest = generate_random_vector(ECC384_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_import_key_verify_invalid_digest_size() {
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

        //not allowed size

        let mut tampered_digest = digest.clone();
        let new_length = tampered_digest.len() - 3;
        tampered_digest.truncate(new_length);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let digest = generate_random_vector(ECC256_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC256_SIG_LEN_LIMIT);

        assert_ne!(signature, digest);

        // not allowed size, large than ECC256_DATA_LEN_LIMIT
        let data = generate_random_vector(4);
        let additional_data: &[u8] = &data;
        tampered_digest.extend_from_slice(additional_data);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        //  allowed size, large than ECC256_DATA_LEN_LIMIT
        let data = generate_random_vector(ECC384_DATA_LEN_LIMIT - ECC256_DATA_LEN_LIMIT);
        let additional_data: &[u8] = &data;
        tampered_digest.extend_from_slice(additional_data);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        //  allowed size, smller than ECC256_DATA_LEN_LIMIT
        let mut tampered_digest = digest.clone();
        let new_length = 20;
        tampered_digest.truncate(new_length);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc256_verify_invalid_sig_size() {
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

        //less than sig size

        let mut tampered_sig = signature.clone();
        let new_length = tampered_sig.len() - 1;
        tampered_sig.truncate(new_length);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);

        // large than sig size
        let mut tampered_sig = signature.clone();
        let data = generate_random_vector(8);
        let additional_data: &[u8] = &data;
        tampered_sig.extend_from_slice(additional_data);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_sign_verify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_sign_verify_tampered_digestdata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_sign_verify_tampered_sig() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_sign_verify_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);

        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(48);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_sign_verify_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        //size 20
        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size 0
        let digest = generate_random_vector(0);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let digest = generate_random_vector(1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC256_DATA_LEN_LIMIT -1, notallowed size
        let digest = generate_random_vector(ECC384_DATA_LEN_LIMIT - 1);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC384_DATA_LEN_LIMIT
        let digest = generate_random_vector(ECC384_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size ECC384_DATA_LEN_LIMIT +1
        let digest = generate_random_vector(ECC384_DATA_LEN_LIMIT + 1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC521_DATA_LEN_LIMIT , noy allowed size
        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_import_key_verify_invalid_digest_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        //not allowed size

        let mut tampered_digest = digest.clone();
        let new_length = tampered_digest.len() - 3;
        tampered_digest.truncate(new_length);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let digest = generate_random_vector(ECC384_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);

        assert_ne!(signature, digest);

        // not allowed size, large than ECC384_DATA_LEN_LIMIT
        let data = generate_random_vector(4);
        let additional_data: &[u8] = &data;
        tampered_digest.extend_from_slice(additional_data);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        //  allowed size, large than ECC384_DATA_LEN_LIMIT
        let data = generate_random_vector(ECC521_DATA_LEN_LIMIT - ECC384_DATA_LEN_LIMIT);
        let additional_data: &[u8] = &data;
        tampered_digest.extend_from_slice(additional_data);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc384_verify_invalid_sig_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC384_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        //less than sig size

        let mut tampered_sig = signature.clone();
        let new_length = tampered_sig.len() - 1;
        tampered_sig.truncate(new_length);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);

        // large than sig size
        let mut tampered_sig = signature.clone();
        let data = generate_random_vector(8);
        let additional_data: &[u8] = &data;
        tampered_sig.extend_from_slice(additional_data);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc521_import_key_sign_verify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc521_import_key_sign_verify_tampered_digestdata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc521_import_key_sign_verify_tampered_sig() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc521_import_key_sign_verify_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(64);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_ecc521_import_key_sign_verify_data_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        //size 20
        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size 0
        let digest = generate_random_vector(0);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let digest = generate_random_vector(1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC521_DATA_LEN_LIMIT -1, notallowed size
        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT - 1);
        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC521_DATA_LEN_LIMIT
        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        //size ECC384_DATA_LEN_LIMIT +1
        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT + 1);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_err(), "result {:?}", result);

        //size ECC384_DATA_LEN_LIMIT ,  allowed size
        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_import_key_ecc521_verify_invalid_digest_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        //not allowed size

        let mut tampered_digest = digest.clone();
        let new_length = tampered_digest.len() - 3;
        tampered_digest.truncate(new_length);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let digest = generate_random_vector(ECC521_DATA_LEN_LIMIT);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);

        assert_ne!(signature, digest);

        //not allowed size, large than ECC521_DATA_LEN_LIMIT
        let data = generate_random_vector(4);
        let additional_data: &[u8] = &data;
        tampered_digest.extend_from_slice(additional_data);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        //allowe size, smaller than ECC521_DATA_LEN_LIMIT
        let mut tampered_digest = digest.clone();
        let new_length = ECC256_DATA_LEN_LIMIT;
        tampered_digest.truncate(new_length);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_import_key_ecc521_verify_invalid_sig_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(20);

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), ECC521_SIG_LEN_LIMIT);
        assert_ne!(signature, digest);

        //less than sig size

        let mut tampered_sig = signature.clone();
        let new_length = tampered_sig.len() - 1;
        tampered_sig.truncate(new_length);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);

        // large than sig size
        let mut tampered_sig = signature.clone();
        let data = generate_random_vector(8);
        let additional_data: &[u8] = &data;
        tampered_sig.extend_from_slice(additional_data);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), tampered_sig.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}
