// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use mcr_ddi_sim::crypto::rsa::RsaOp;
use test_with_tracing::test;

use crate::common::*;

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
        let target_key_handle = result.unwrap();

        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &target_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        // Decrypt pre-enc data: can't enc no pub in mcr.
        let result = app_session.rsa_decrypt(
            &target_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);
    });
}

#[test]
fn test_get_unwrapping_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Get handle to private wrapping key
        let wrapping_key = get_unwrapping_key(&app_session);

        let result = app_session.export_public_key(&wrapping_key);
        assert!(result.is_ok(), "result {:?}", result);
        let wrapping_key_der = result.unwrap();

        // Wrap data using the public wrapping key
        let (wrapped_blob, public_key_der) = generate_wrapped_data(wrapping_key_der);

        // Unwrap key in wrapped_blob
        let wrapped_blob_params = RsaUnwrapParams {
            key_class: KeyClass::Rsa,
            padding: RsaCryptoPadding::Oaep,
            hash_algorithm: DigestKind::Sha1,
        };

        let result = app_session.rsa_unwrap(
            &wrapping_key,
            wrapped_blob,
            wrapped_blob_params,
            None,
            KeyProperties {
                key_usage: (KeyUsage::EncryptDecrypt),
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_handle = result.unwrap();

        // Verify the public key in wrapped_key_handle is the same as the generated public key
        let result = app_session.export_public_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
        let wrapped_key_pub = result.unwrap();
        assert_eq!(wrapped_key_pub, public_key_der);

        // Encrypt using pub_key in wrapped_key_handle
        let message = vec![0x1, 0x3, 0x5, 0x7, 0x9, 0xA, 0xC, 0xF];
        let result = app_session.rsa_encrypt(
            &wrapped_key_handle,
            message.clone(),
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.rsa_decrypt(
            &wrapped_key_handle,
            encrypted_data,
            RsaCryptoPadding::Oaep,
            Some(DigestKind::Sha256),
            None,
        );
        assert!(result.is_ok(), "result {:?}", result);
        let dec_data = result.unwrap();

        // Verify the round-tripped message is correct.
        assert_eq!(dec_data, message);

        let result = app_session.delete_key(&wrapped_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

/// This private function generates a private 3k RSA key,
/// wraps it using input wrapping_key_der using OpenSSL,
/// then returns the wrapped data, and the counterpart public 3k RSA key
///
/// # Arguments
/// * `wrapping_key_der` - Public key to wrap with, in DER format
///
/// # Returns
/// * `(Vec<u8>, Vec<u8>)` - The wrapped private 3k RSA key,
///   and corresponding public 3k RSA key in DER format
fn generate_wrapped_data(wrapping_key_der: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let (rsa_priv, rsa_pub) =
        mcr_ddi_sim::crypto::rsa::generate_rsa(3072).expect("Failed to generate RSA key");
    let target_der = rsa_priv.to_der().unwrap();
    let public_key_der = rsa_pub.to_der().unwrap();

    let wrapped_key = wrap_data(wrapping_key_der, &target_der);

    (wrapped_key, public_key_der)
}
