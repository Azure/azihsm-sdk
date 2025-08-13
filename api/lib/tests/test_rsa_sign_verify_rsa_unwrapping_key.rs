// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key2k_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivateCrt,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pss_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pss_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pkcs1_5() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pkcs1_5_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_2k_sign_verify_pkcs1_5_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa2kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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

        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivateCrt,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pss_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pss_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pkcs1_5() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pkcs1_5_tampereddata() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_3k_sign_verify_pkcs1_5_multi_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa3kPrivate,
            DigestKind::Sha1,
            KeyUsage::SignVerify,
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_4k_unwrap_key_crt_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = generate_random_vector(32);

        let result = rsa_unwrap_from_wrap_data(
            &app_session,
            KeyType::Rsa4kPrivateCrt,
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

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest.clone(),
            signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pss_tampereddata() {
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pss_multi_times() {
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pkcs1_5() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pkcs1_5_tampereddata() {
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_rsa_unwrap_key_4k_sign_verify_pkcs1_5_multi_times() {
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
        let result = app_session.delete_key(&priv_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
