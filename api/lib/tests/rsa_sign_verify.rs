// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "testhooks")]
use mcr_api::*;
#[cfg(feature = "testhooks")]
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_rsa_2k_sign_verify_pss() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let digest = vec![1u8; 32];

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
        assert_eq!(signature.len(), 256);
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

        let mut tampered_signature = signature;
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest,
            tampered_signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);

        let digest = vec![1u8; 32];

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
        assert_eq!(signature.len(), 256);
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

        let mut tampered_signature = signature;
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.rsa_verify(
            &priv_key_handle,
            digest,
            tampered_signature.clone(),
            RsaSignaturePadding::Pss,
            None,
            None,
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}
