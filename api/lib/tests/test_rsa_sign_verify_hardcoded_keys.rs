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
fn test_rsa_2k_sign_verify_pss() {
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
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
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
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pss_tampered_digestdata() {
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

        let digest = generate_random_vector(32);

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

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
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
fn test_rsa_2k_sign_verify_pss_tampered_sig() {
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

        let digest = generate_random_vector(32);

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

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pss_multi_times() {
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

        let digest = generate_random_vector(32);
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
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
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
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
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
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
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
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pkcs1_5() {
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
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
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
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(48);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
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
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(64);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
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
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pkcs1_5_tampereddata() {
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

        let digest = generate_random_vector(32);

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

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pkcs1_5_multi_times() {
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

        let digest = generate_random_vector(32);
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
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
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
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
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
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
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
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

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

        let result = app_session.rsa_verify(
            &priv_key_handle,
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
fn test_rsa_3k_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_3K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
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

        let result = app_session.rsa_verify(
            &priv_key_handle,
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
fn test_rsa_3k_sign_verify_pss_tampered_digestdata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(32);

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

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
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
fn test_rsa_3k_sign_verify_pss_tampered_sig() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(32);

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

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_sign_verify_pss_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(32);
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

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_sign_verify_pkcs1_5() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

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
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(48);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(64);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_sign_verify_pkcs1_5_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_3k_sign_verify_pkcs1_5_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_3K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
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
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
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
fn test_rsa_4k_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::RsaCrt,
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
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
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
fn test_rsa_4k_sign_verify_pss_tampered_digestdata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(32);

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

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
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
fn test_rsa_4k_sign_verify_pss_tampered_sig() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(32);

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

        let mut tampered_signature = signature.clone();
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            tampered_signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_sign_verify_pss_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(32);
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

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_sign_verify_pkcs1_5() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
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
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(48);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        let digest = generate_random_vector(64);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_sign_verify_pkcs1_5_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(32);

        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            tampered_digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_4k_sign_verify_pkcs1_5_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.import_key(
            TEST_RSA_4K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha 256
        let digest = generate_random_vector(32);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha384
        let digest = generate_random_vector(48);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha384),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);

        //sha512
        let digest = generate_random_vector(64);
        let result = app_session.rsa_sign(
            &priv_key_handle,
            digest.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), RSA_4K_DATA_SIZE_LIMIT);
        assert_ne!(signature, digest);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pkcs1_5,
            Some(DigestKind::Sha512),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}
