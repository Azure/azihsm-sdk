// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_sign_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let digest = generate_random_vector(20);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
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

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_sign_datasize_not_euqal_hash_len() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(64);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.clone().is_err());

        let digest = generate_random_vector(20);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.clone().is_err());

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.clone().is_err());

        let digest = generate_random_vector(48);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.clone().is_err());
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_sign_verify_nonmatching_padding() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_sign_verify_pss_nonmatching_hash() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        // Verify with a different hash
        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_sign_verify_key_type_encrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(20);

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

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_sign_invalid_keyhandle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(20);

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

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_verify_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_verify_with_mew_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.rsa_verify(
            &priv_key_handle1,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_verify_with_handle_encrypt_type() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

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
        let priv_key_handle1 = result.unwrap();

        let result = app_session.rsa_verify(
            &priv_key_handle1,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_verify_after_session_invalid_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
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

        let result = app_session.rsa_verify(
            &priv_key_handle1,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        // assert!(result.is_ok(), "result {:?}", result);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_verify_invalid_sig_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_2K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_sig = signature.clone();

        let data = generate_random_vector(4);
        let additional_data: &[u8] = &data;
        tampered_sig.extend_from_slice(additional_data);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_sig.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        //3k
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

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_sig = signature.clone();
        tampered_sig.truncate(RSA_2K_DATA_SIZE_LIMIT);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_sig.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        //4k

        let digest = generate_random_vector(32);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_sig = signature.clone();
        tampered_sig.truncate(RSA_2K_DATA_SIZE_LIMIT / 4);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_sig.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );

        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
