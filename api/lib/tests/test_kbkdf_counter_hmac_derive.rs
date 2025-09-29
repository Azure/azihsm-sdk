// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_key_kbkdf() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let result = app_session.kbkdf_counter_hmac_derive(
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
    });
}

#[test]
fn test_key_kbkdf_after_session_close() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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
        let _secret2 = result.unwrap();

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_key_kbkdf_non_secret_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &priv_key_handle1,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_key_kbkdf_invalid_target_type() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Rsa2kPrivate,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params,
            None,
            KeyType::Ecc256Private,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_key_kbkdf_invalid_target_usage() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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
        let _secret2 = result.unwrap();

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Aes192,
            KeyProperties {
                key_usage: KeyUsage::Unwrap,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret1,
            params,
            None,
            KeyType::Aes128,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_key_kbkdf_non_matching_key_type() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params,
            None,
            KeyType::Aes192,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert AES keys are different via encrypt/decrypt
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

        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_key_kbkdf_non_matching_key_availability() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
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

        let result = app_session.delete_key(&symmetric_key2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_key_kbkdf_nonmatching_label() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let label_bytes = "label1".as_bytes();
        let context_bytes = "context".as_bytes();

        let params2 = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params2,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert AES keys are different via encrypt/decrypt
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

        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_key_kbkdf_nonmatching_context() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let label_bytes = "label".as_bytes();
        let context_bytes = "context1".as_bytes();

        let params2 = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params2,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert AES keys are different via encrypt/decrypt
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

        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_key_kbkdf_nonmatching_hash() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params2 = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha384,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
            &secret2,
            params2,
            None,
            KeyType::Aes256,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let symmetric_key2 = result.unwrap();

        // Assert AES keys are different via encrypt/decrypt
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

        assert_ne!(decrypted_data.data, data);
    });
}

#[test]
fn test_key_kbkdf_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        let result = app_session.kbkdf_counter_hmac_derive(
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
            &symmetric_key2,
            AesMode::Encrypt,
            data.clone(),
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();

        let result = app_session.aes_encrypt_decrypt(
            &symmetric_key1,
            AesMode::Decrypt,
            encrypted_data.data,
            [0x0; 16],
        );
        assert!(result.is_ok(), "result {:?}", result);
        let decrypted_data = result.unwrap();

        assert_eq!(decrypted_data.data, data);

        // Use KBKDF to derive an AES key from each secret
        let label_bytes = "label2".as_bytes();
        let context_bytes = "context2".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };
        let result = app_session.kbkdf_counter_hmac_derive(
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

        let result = app_session.kbkdf_counter_hmac_derive(
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
    });
}

#[test]
fn test_key_exchange_encode_kbkdf_decode_hkdf() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two ECC key pairs
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

        // Key exchange with each cross pair
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

        let label_bytes = "label".as_bytes();
        let context_bytes = "context".as_bytes();

        let params = KbkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            label: Some(label_bytes),
            context: Some(context_bytes),
        };

        let result = app_session.kbkdf_counter_hmac_derive(
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

        // Use HKDF to derive a new secret from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

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

        // Assert AES keys are different via encrypt/decrypt
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

        assert_ne!(decrypted_data.data, data);
    });
}
