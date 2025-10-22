// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecdh_key_256_exchange_eccgen_aes256_encrypt_decrypt() {
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
    });
}

#[test]
fn test_ecdh_key_256_exchange_eccgen_aes128_encrypt_decrypt() {
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
            KeyType::Aes128,
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
            KeyType::Aes128,
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
fn test_ecdh_key_256_exchange_eccgen_aes192_encrypt_decrypt() {
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
            KeyType::Aes192,
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
            KeyType::Aes192,
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
fn test_ecdh_key_384_exchange_eccgen_aes256_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P384,
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
            KeyType::Secret384,
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
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret2 = result.unwrap();

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
    });
}

#[test]
fn test_ecdh_key_384_exchange_eccgen_aes128_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P384,
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
            KeyType::Secret384,
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
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret2 = result.unwrap();

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
            KeyType::Aes128,
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
            KeyType::Aes128,
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
fn test_ecdh_key_384_exchange_eccgen_aes192_encrypt_decrypt() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Generate two key pairs
        let result = app_session.ecc_generate(
            EccCurve::P384,
            None,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle1 = result.unwrap();

        let result = app_session.ecc_generate(
            EccCurve::P384,
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
            KeyType::Secret384,
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
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let secret2 = result.unwrap();

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
            KeyType::Aes192,
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
            KeyType::Aes192,
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
fn test_ecdh_key_521_exchange_eccgen_aes256_encrypt_decrypt() {
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
    });
}

#[test]
fn test_ecdh_key_521_exchange_eccgen_aes128_encrypt_decrypt() {
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
            KeyType::Aes128,
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
            KeyType::Aes128,
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
fn test_ecdh_key_521_exchange_eccgen_aes192_encrypt_decrypt() {
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
            KeyType::Aes192,
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
            KeyType::Aes192,
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
