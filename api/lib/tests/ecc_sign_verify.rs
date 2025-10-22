// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecc_256_sign_verify() {
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

        let digest = vec![1u8; 20];

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 64);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let mut tampered_signature = signature;
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.ecc_verify(&priv_key_handle, digest, tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecc_384_sign_verify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = vec![1u8; 20];

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 96);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let mut tampered_signature = signature;
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.ecc_verify(&priv_key_handle, digest, tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecc_521_sign_verify() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();

        let digest = vec![1u8; 20];

        let result = app_session.ecc_sign(&priv_key_handle, digest.clone());
        assert!(result.is_ok(), "result {:?}", result);
        let signature = result.unwrap();
        assert_eq!(signature.len(), 132);
        assert_ne!(signature, digest);

        let result = app_session.ecc_verify(&priv_key_handle, digest.clone(), signature.clone());
        assert!(result.is_ok(), "result {:?}", result);

        let mut tampered_digest = digest.clone();
        tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

        let result =
            app_session.ecc_verify(&priv_key_handle, tampered_digest.clone(), signature.clone());
        assert!(result.is_err(), "result {:?}", result);

        let mut tampered_signature = signature;
        tampered_signature[0] = tampered_signature[0].wrapping_add(0x1);

        let result = app_session.ecc_verify(&priv_key_handle, digest, tampered_signature.clone());
        assert!(result.is_err(), "result {:?}", result);
    });
}
