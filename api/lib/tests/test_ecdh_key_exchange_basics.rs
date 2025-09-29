// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

/// ECDH Key Exchange
///
/// # Arguments
/// `priv_key` - Own private key, must be Ecc Private type, must have KeyUsage `Derive`
/// `peer_pub_key` - Other party's public key, must be Ecc Public type and same curve name as `priv_key`
/// `target_key_tag` - Target key tag
/// `target_key_type` - Target key type, must be `Secret` type with matching bit size
/// `target_key_properties` - Target key properties, must be `Derive` usage.
///
/// # Returns
/// Result has KeyType `Secret` and KeyUsage `Derive`
///
///
#[test]
fn test_ecdh_key_exchange_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Generate two key pairs
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
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Confirm we can key exchange with either cross pair
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
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_secrets_non_ecc_privatekey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let priv_key_handle1 = get_unwrapping_key(&app_session);

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
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_non_derive_ecckey() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
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
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_non_matching_curve() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);
    });
}
#[test]
fn test_ecdh_key_exchange_non_matching_key_availibility() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P256,
            None,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_pubkey_nonecctype() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        let priv_key_handle3 = get_unwrapping_key(&app_session);

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle3);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_rsa_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        let _secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_rsa_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_pubkey_nonmatching_curve() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle3 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle3);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_cee521_der = result.unwrap();

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_cee521_der,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret2 = result.unwrap();
    });
}

#[test]
fn test_ecdh_key_exchange_pubkey_size() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        //normal szie:

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();

        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();

        // Confirm we can key exchange with either cross pair
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
        let secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret2 = result.unwrap();

        //size 0
        let mut tampered_pub = pub_key_der2.clone();
        let new_length = 0;
        tampered_pub.truncate(new_length);
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        //size 1
        let mut tampered_pub = pub_key_der2.clone();
        let new_length = 1;
        tampered_pub.truncate(new_length);
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        //less than pub_key_der2 size
        let mut tampered_pub = pub_key_der2.clone();
        let new_length = pub_key_der2.len() - 1;
        tampered_pub.truncate(new_length);
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);

        //larger than pub_key_der2 size
        let mut tampered_pub = pub_key_der2.clone();

        let data = generate_random_vector(3);
        let additional_data: &[u8] = &data;
        tampered_pub.extend_from_slice(additional_data);

        let _result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );

        // BUG: this should be error

        //size 192
        let mut tampered_pub = pub_key_der2.clone();

        let new_len = 192 - pub_key_der2.len();
        let data = generate_random_vector(new_len);
        let additional_data: &[u8] = &data;
        tampered_pub.extend_from_slice(additional_data);

        let _result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );

        // BUG: this should be error

        //size 190 < 192
        let mut tampered_pub = pub_key_der2.clone();

        let new_len = 192 - 2 - pub_key_der2.len();
        let data = generate_random_vector(new_len);
        let additional_data: &[u8] = &data;
        tampered_pub.extend_from_slice(additional_data);

        let _result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );

        // BUG: this should be error

        // Use HKDF to derive an AES key from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

        let result = app_session.hkdf_derive(
            &secret1,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key1 = result.unwrap();

        let result = app_session.hkdf_derive(
            &secret2,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert the AES keys are the same via encrypt/decrypt
        let data = vec![1; 128];
        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key1,
            AesMode::Encrypt,
            data.clone(),
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key2,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data.data, data);

        //size 200 > 196
        let mut tampered_pub = pub_key_der2.clone();

        let new_len = 192 + 4 - pub_key_der2.len();
        let data = generate_random_vector(new_len);
        let additional_data: &[u8] = &data;
        tampered_pub.extend_from_slice(additional_data);

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_tampered() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        //tampered pub1
        let mut tampered_pub = pub_key_der2.clone();
        tampered_pub[0] = pub_key_der2[0].wrapping_add(0x1);

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &tampered_pub,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_non_secret_targetkeytype() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Ecc256Private,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_secret_notmatching_curvesize() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        // This err can be either MborEncodeError or DdiStatus based on environment
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_secret_nonderive() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
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

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_ecdh_key_exchange_multipletimes() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle2 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P521,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle3 = result.unwrap();

        // Get the DER from key handle
        let result = app_session.export_public_key(&priv_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der1 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der2 = result.unwrap();
        let result = app_session.export_public_key(&priv_key_handle3);
        assert!(result.is_ok(), "result {:?}", result);
        let pub_key_der3 = result.unwrap();

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret2 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle3,
            &pub_key_der1,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret3 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der3,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret4 = result.unwrap();

        // Use HKDF to derive an AES key from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

        let result = app_session.hkdf_derive(
            &secret1,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key1 = result.unwrap();

        let result = app_session.hkdf_derive(
            &secret2,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert the AES keys are the same via encrypt/decrypt
        let data = generate_random_vector(128);

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key1,
            AesMode::Encrypt,
            data.clone(),
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key2,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data.data, data);

        let result = app_session.hkdf_derive(
            &secret3,
            params,
            None,
            KeyType::Aes192,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key3 = result.unwrap();

        let result = app_session.hkdf_derive(
            &secret4,
            params,
            None,
            KeyType::Aes192,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key4 = result.unwrap();

        // Assert the AES keys are the same via encrypt/decrypt
        let data = generate_random_vector(128);

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key3,
            AesMode::Encrypt,
            data.clone(),
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key4,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data.data, data);
    });
}
