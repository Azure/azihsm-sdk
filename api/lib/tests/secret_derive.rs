// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_key_exchange_kbkdf() {
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
    });
}
