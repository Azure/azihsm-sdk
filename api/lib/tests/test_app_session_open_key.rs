// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
#[cfg(not(feature = "resilient"))]
use mcr_api::*;
#[cfg(feature = "resilient")]
use mcr_api_resilient::*;
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::TEST_RSA_2K_PRIVATE_KEY;
#[cfg(feature = "testhooks")]
use crate::common::TEST_RSA_2K_PUBLIC_KEY;
use crate::common::*;

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_when_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x7677;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _pri_key_id = result.unwrap();

        let result = app_session.delete_key(&_pri_key_id);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.open_key(key_tag);
        assert!(result.is_err(), "result {:?}", result);

        //clean  up
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_non_matching_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x7678;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _pri_key_id = result.unwrap();

        let key_tag1 = key_tag + 1;
        let result = app_session.open_key(key_tag1);
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.delete_key(&_pri_key_id);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_without_import_key() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x7679;

        let result = app_session.open_key(key_tag);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_invalid_tag() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import an App key with a specified tag
        let key_tag = 0x0;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_err(), "result {:?}", result);

        let result = app_session.open_key(key_tag);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        // Import a Session Key with key tag is not allowed
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(0x6677),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_err(), "result {:?}", result);
        if let Err(err) = result {
            assert_eq!(err, HsmError::InvalidParameter);
        }
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        // Import an App key with a specified tag
        let key_tag = 0x7680;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let pri_key_id = result.unwrap();

        // Import a key with a different tag
        let key_tag2 = key_tag + 1;
        let result = app_session.import_key(
            TEST_RSA_2K_PRIVATE_KEY.to_vec(),
            KeyClass::Rsa,
            Some(key_tag2),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let pri_key_id2 = result.unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle1 = result.unwrap();

        let result = app_session.open_key(key_tag2);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle2 = result.unwrap();

        let result = app_session.export_public_key(&pri_key_id);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_pub_key = result.unwrap();

        let result = app_session.export_public_key(&key_handle1);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_key1 = result.unwrap();

        assert_eq!(exported_pub_key, exported_key1);

        let result = app_session.export_public_key(&pri_key_id2);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_pub_key2 = result.unwrap();

        let result = app_session.export_public_key(&key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
        let exported_key2 = result.unwrap();

        assert_eq!(exported_pub_key2, exported_key2);

        let result = app_session.delete_key(&key_handle1);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_rsa_2k() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            {
                // Import a private key with a specified tag, from der
                let key_tag = 0x7723;
                let result = app_session.import_key(
                    TEST_RSA_2K_PRIVATE_KEY.to_vec(),
                    KeyClass::Rsa,
                    Some(key_tag),
                    KeyProperties {
                        key_usage: KeyUsage::SignVerify,
                        key_availability: KeyAvailability::App,
                    },
                );
                assert!(result.is_ok(), "result {:?}", result);
                let priv_key_handle = result.unwrap();
                let result = app_session.export_public_key(&priv_key_handle);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key = result.unwrap();
                assert_eq!(raw_key, TEST_RSA_2K_PUBLIC_KEY.to_vec());

                let result = app_session.open_key(key_tag);
                assert!(result.is_ok(), "result {:?}", result);
                let key_handle2 = result.unwrap();
                let result = app_session.export_public_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key2 = result.unwrap();
                assert_eq!(raw_key, raw_key2);

                let result = app_session.delete_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
            }
        }
    });
}
#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_rsa_3k() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            {
                // Import a private key with a specified tag, from der
                let key_tag = 0x7925;
                let result = app_session.import_key(
                    TEST_RSA_3K_PRIVATE_KEY.to_vec(),
                    KeyClass::Rsa,
                    Some(key_tag),
                    KeyProperties {
                        key_usage: KeyUsage::SignVerify,
                        key_availability: KeyAvailability::App,
                    },
                );
                assert!(result.is_ok(), "result {:?}", result);
                let priv_key_handle = result.unwrap();
                let result = app_session.export_public_key(&priv_key_handle);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key = result.unwrap();
                assert_eq!(raw_key, TEST_RSA_3K_PUBLIC_KEY.to_vec());

                let result = app_session.open_key(key_tag);
                assert!(result.is_ok(), "result {:?}", result);
                let key_handle2 = result.unwrap();
                let result = app_session.export_public_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key2 = result.unwrap();
                assert_eq!(raw_key, raw_key2);

                let result = app_session.delete_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
            }
        }
    });
}
#[test]
#[cfg(feature = "testhooks")]
fn test_open_key_rsa_4k() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            {
                // Import a private key with a specified tag, from der
                let key_tag = 0x7924;
                let result = app_session.import_key(
                    TEST_RSA_4K_PRIVATE_KEY.to_vec(),
                    KeyClass::Rsa,
                    Some(key_tag),
                    KeyProperties {
                        key_usage: KeyUsage::SignVerify,
                        key_availability: KeyAvailability::App,
                    },
                );
                assert!(result.is_ok(), "result {:?}", result);
                let priv_key_handle = result.unwrap();
                let result = app_session.export_public_key(&priv_key_handle);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key = result.unwrap();
                assert_eq!(raw_key, TEST_RSA_4K_PUBLIC_KEY.to_vec());

                let result = app_session.open_key(key_tag);
                assert!(result.is_ok(), "result {:?}", result);
                let key_handle2 = result.unwrap();
                let result = app_session.export_public_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
                let raw_key2 = result.unwrap();
                assert_eq!(raw_key, raw_key2);

                let result = app_session.delete_key(&key_handle2);
                assert!(result.is_ok(), "result {:?}", result);
            }
        }
    });
}

#[test]
fn test_open_key_ecc256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import a key with a specified tag, from ecc_generate
        let key_tag = 0x7728;
        let result = app_session.ecc_generate(
            EccCurve::P256,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();
        let raw_key_pub = app_session.export_public_key(&priv_key_handle).unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle = result.unwrap();
        let result = app_session.export_public_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
        let raw_key = result.unwrap();
        assert_eq!(raw_key_pub, raw_key);

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_ecc384() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import a key with a specified tag, from ecc_generate
        let key_tag = 0x7729;
        let result = app_session.ecc_generate(
            EccCurve::P384,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();
        let raw_key_pub = app_session.export_public_key(&priv_key_handle).unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle = result.unwrap();
        let result = app_session.export_public_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
        let raw_key = result.unwrap();
        assert_eq!(raw_key_pub, raw_key);

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_ecc521() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import a key with a specified tag, from ecc_generate
        let key_tag = 0x7730;
        let result = app_session.ecc_generate(
            EccCurve::P521,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::SignVerify,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let priv_key_handle = result.unwrap();
        let raw_key_pub = app_session.export_public_key(&priv_key_handle).unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle = result.unwrap();
        let result = app_session.export_public_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
        let raw_key = result.unwrap();
        assert_eq!(raw_key_pub, raw_key);

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_aes128() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            // Import a key with a specified tag, from aes_generate
            let key_tag = 0x7724;

            let result = app_session.aes_generate(
                AesKeySize::Aes128,
                Some(key_tag),
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let aes_key_handle = result.unwrap();

            let result = app_session.open_key(key_tag);
            assert!(result.is_ok(), "result {:?}", result);
            let key_handle = result.unwrap();

            let data = generate_random_vector(128);
            let result = app_session.aes_encrypt_decrypt(
                &aes_key_handle,
                AesMode::Encrypt,
                data.clone(),
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let encrypted_data = result.unwrap();
            assert_eq!(encrypted_data.data.len(), data.len());
            assert_ne!(data, encrypted_data.data);

            let result = app_session.aes_encrypt_decrypt(
                &key_handle,
                AesMode::Decrypt,
                encrypted_data.data,
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let decrypted_data = result.unwrap();
            assert_eq!(decrypted_data.data.len(), data.len());
            assert_eq!(decrypted_data.data, data);

            let result = app_session.delete_key(&key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

#[test]
fn test_open_key_aes192() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            // Import a key with a specified tag, from aes_generate
            let key_tag = 0x7725;

            let result = app_session.aes_generate(
                AesKeySize::Aes192,
                Some(key_tag),
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let aes_key_handle = result.unwrap();

            let result = app_session.open_key(key_tag);
            assert!(result.is_ok(), "result {:?}", result);
            let key_handle = result.unwrap();

            let data = generate_random_vector(128);
            let result = app_session.aes_encrypt_decrypt(
                &aes_key_handle,
                AesMode::Encrypt,
                data.clone(),
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let encrypted_data = result.unwrap();
            assert_eq!(encrypted_data.data.len(), data.len());
            assert_ne!(data, encrypted_data.data);

            let result = app_session.aes_encrypt_decrypt(
                &key_handle,
                AesMode::Decrypt,
                encrypted_data.data,
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let decrypted_data = result.unwrap();
            assert_eq!(decrypted_data.data.len(), data.len());
            assert_eq!(decrypted_data.data, data);

            let result = app_session.delete_key(&key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

#[test]
fn test_open_key_aes256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        {
            // Import a key with a specified tag, from aes_generate
            let key_tag = 0x7726;

            let result = app_session.aes_generate(
                AesKeySize::Aes256,
                Some(key_tag),
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            assert!(result.is_ok(), "result {:?}", result);
            let aes_key_handle = result.unwrap();

            let result = app_session.open_key(key_tag);
            assert!(result.is_ok(), "result {:?}", result);
            let key_handle = result.unwrap();

            let data = generate_random_vector(128);
            let result = app_session.aes_encrypt_decrypt(
                &aes_key_handle,
                AesMode::Encrypt,
                data.clone(),
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let encrypted_data = result.unwrap();
            assert_eq!(encrypted_data.data.len(), data.len());
            assert_ne!(data, encrypted_data.data);

            let result = app_session.aes_encrypt_decrypt(
                &key_handle,
                AesMode::Decrypt,
                encrypted_data.data,
                [0x1; 16],
            );

            assert!(result.is_ok(), "result {:?}", result);
            let decrypted_data = result.unwrap();
            assert_eq!(decrypted_data.data.len(), data.len());
            assert_eq!(decrypted_data.data, data);

            let result = app_session.delete_key(&key_handle);
            assert!(result.is_ok(), "result {:?}", result);
        }
    });
}

#[test]
fn test_open_key_aesbulk() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Import a key with a specified tag, from aes_generate
        let key_tag = 0x7727;

        let result = app_session.aes_generate(
            AesKeySize::AesGcmBulk256Unapproved,
            Some(key_tag),
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let aes_key_handle = result.unwrap();

        let result = app_session.open_key(key_tag);
        assert!(result.is_ok(), "result {:?}", result);
        let key_handle = result.unwrap();

        let data = generate_random_vector(256);
        let aad = generate_random_vector(32);
        let iv = [0x3u8; 12];

        let result = app_session.aes_gcm_encrypt_decrypt(
            &aes_key_handle,
            AesMode::Encrypt,
            data.clone(),
            iv,
            Some(aad.clone()),
            None, /* tag is not needed for encryption */
        );
        assert!(result.is_ok(), "result {:?}", result);
        let encrypted_data = result.unwrap();
        assert_eq!(encrypted_data.data.len(), data.len());
        assert_ne!(data, encrypted_data.data);
        let tag = encrypted_data.tag;

        let result = app_session.aes_gcm_encrypt_decrypt(
            &key_handle,
            AesMode::Decrypt,
            encrypted_data.data.clone(),
            iv,
            Some(aad.clone()),
            tag,
        );
        assert!(
            result.is_ok(),
            "{:?} AesKeyHandle{:?} OpenKeyHandle{:?}",
            result,
            &aes_key_handle,
            key_handle
        );
        let decrypted_data = result.unwrap();
        assert_eq!(decrypted_data.data.len(), data.len());
        assert_eq!(decrypted_data.data, data);

        let result = app_session.delete_key(&key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_secret256() {
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

        let key_tag1 = 0x7731;

        let key_tag2 = 0x6267;

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            Some(key_tag1),
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            Some(key_tag2),
            KeyType::Secret256,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret2 = result.unwrap();

        let result = app_session.open_key(key_tag1);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle1 = result.unwrap();

        let result = app_session.open_key(key_tag2);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle2 = result.unwrap();

        // Use HKDF to derive an AES key from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

        let result = app_session.hkdf_derive(
            &secret_key_handle1,
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
            &secret_key_handle2,
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

        let result = app_session.delete_key(&secret_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&secret_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_secret384() {
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

        let key_tag1 = 0x7733;

        let key_tag2 = 0x6270;

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            Some(key_tag1),
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            Some(key_tag2),
            KeyType::Secret384,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret2 = result.unwrap();

        let result = app_session.open_key(key_tag1);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle1 = result.unwrap();

        let result = app_session.open_key(key_tag2);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle2 = result.unwrap();

        // Use HKDF to derive an AES key from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

        let result = app_session.hkdf_derive(
            &secret_key_handle1,
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
            &secret_key_handle2,
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

        let result = app_session.delete_key(&secret_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&secret_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_key_secret521() {
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

        let key_tag1 = 0x7735;

        let key_tag2 = 0x6274;

        // Confirm we can key exchange with either cross pair
        let result = app_session.ecdh_key_exchange(
            &priv_key_handle1,
            &pub_key_der2,
            Some(key_tag1),
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret1 = result.unwrap();

        let result = app_session.ecdh_key_exchange(
            &priv_key_handle2,
            &pub_key_der1,
            Some(key_tag2),
            KeyType::Secret521,
            KeyProperties {
                key_usage: KeyUsage::Derive,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);
        let _secret2 = result.unwrap();

        let result = app_session.open_key(key_tag1);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle1 = result.unwrap();

        let result = app_session.open_key(key_tag2);
        assert!(result.is_ok(), "result {:?}", result);
        let secret_key_handle2 = result.unwrap();

        // Use HKDF to derive an AES key from each secret
        let salt_bytes = "salt".as_bytes();
        let info_bytes = "label".as_bytes();

        let params = HkdfDeriveParameters {
            hash_algorithm: DigestKind::Sha256,
            salt: Some(salt_bytes),
            info: Some(info_bytes),
        };

        let result = app_session.hkdf_derive(
            &secret_key_handle1,
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
            &secret_key_handle2,
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

        let result = app_session.delete_key(&secret_key_handle1);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.delete_key(&secret_key_handle2);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
