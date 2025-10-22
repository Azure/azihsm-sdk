// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

#[cfg(feature = "testhooks")]
use crate::common::TEST_RSA_4K_PRIVATE_KEY;
use crate::common::*;

#[test]
fn test_close_session() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let _app_session = common_open_app_session(device);
    });
}

#[test]
fn test_close_session_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.close_session();
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_close_session_after_mgr_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let _app_session = common_open_app_session(device);
    });
}

#[test]
fn test_close_session_delete_app() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::Session,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.aes_generate(
            AesKeySize::Aes256,
            None,
            KeyProperties {
                key_usage: KeyUsage::EncryptDecrypt,
                key_availability: KeyAvailability::App,
            },
        );
        assert!(result.is_ok(), "result {:?}", result);

        let aes_key_handle = result.unwrap();

        let result = app_session.delete_key(&aes_key_handle);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_close_session_exhaust_session_keys() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let mut key_count_round1 = 0;
        loop {
            let result = app_session.import_key(
                TEST_RSA_4K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            if result.is_ok() {
                key_count_round1 += 1;
            } else {
                break;
            }
        }

        println!(
            "Round 1: Vault exhausted after creating {} session only keys(RSA4K)",
            key_count_round1
        );

        assert!(key_count_round1 >= 1);

        // close session should delete all session keys in the vault
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Create a new session after key exhaustion and reclaiming of key vault
        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        let mut key_count_round2 = 0;
        loop {
            let result = app_session.import_key(
                TEST_RSA_4K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            if result.is_ok() {
                key_count_round2 += 1;
            } else {
                break;
            }
        }

        println!(
            "Round 2: Vault exhausted after creating {} session only keys(RSA4K)",
            key_count_round2
        );

        assert!(key_count_round2 >= 1);

        // check if we are able to recreate the same number of keys
        assert_eq!(key_count_round1, key_count_round2);
    });
}

#[test]
#[cfg(feature = "testhooks")]
fn test_close_session_exhaust_app_keys() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let mut key_count_round1 = 0;
        let mut keys_created = Vec::new();

        loop {
            let result = app_session.import_key(
                TEST_RSA_4K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            if let Ok(key) = result {
                key_count_round1 += 1;
                keys_created.push(key);
            } else {
                break;
            }
        }

        println!(
            "Round 1: Vault exhausted after creating {} app only keys(RSA4K)",
            key_count_round1
        );

        assert!(key_count_round1 >= 1);

        // Delete all the keys again
        for key in keys_created {
            let result = app_session.delete_key(&key);
            assert!(result.is_ok());
        }

        // close session only deletes session only keys in the vault. So nop for
        // this test case wrt to key deletion.
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Create a new session after key exhaustion and reclaiming of key vault
        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        let mut key_count_round2 = 0;
        let mut keys_created = Vec::new();

        loop {
            let result = app_session.import_key(
                TEST_RSA_4K_PRIVATE_KEY.to_vec(),
                KeyClass::Rsa,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            if let Ok(key) = result {
                key_count_round2 += 1;
                keys_created.push(key);
            } else {
                break;
            }
        }

        println!(
            "Round 2: Vault exhausted after creating {} app only keys(RSA4K)",
            key_count_round2
        );

        assert!(key_count_round2 >= 1);

        // check if we are able to recreate the same number of keys
        assert_eq!(key_count_round1, key_count_round2);

        // close session only deletes session only keys in the vault. So nop for
        // this test case wrt to key deletion.

        // Delete all the keys again
        for key in keys_created {
            let result = app_session.delete_key(&key);
            assert!(result.is_ok());
        }
    });
}

#[test]
fn test_close_session_exhaust_session_keys_aes_bulk256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let mut key_count_round1 = 0;
        loop {
            let result = app_session.aes_generate(
                AesKeySize::AesXtsBulk256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            if result.is_ok() {
                key_count_round1 += 1;
            } else {
                println!("failed in aes_generate {:?}", result.err());
                break;
            }
        }

        println!(
            "Round 1: Vault exhausted after creating {} session only keys(Aes Bulk 256)",
            key_count_round1
        );

        assert!(key_count_round1 >= 1);

        // close session should delete all session keys in the vault
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Create a new session after key exhaustion and reclaiming of key vault
        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        let mut key_count_round2 = 0;
        loop {
            let result = app_session.aes_generate(
                AesKeySize::AesXtsBulk256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::Session,
                },
            );
            if result.is_ok() {
                key_count_round2 += 1;
            } else {
                break;
            }
        }

        println!(
            "Round 2: Vault exhausted after creating {} session only keys(Aes Bulk 256)",
            key_count_round2
        );

        assert!(key_count_round2 >= 1);

        // check if we are able to recreate the same number of keys
        assert_eq!(key_count_round1, key_count_round2);
    });
}

#[test]
fn test_close_session_exhaust_app_keys_aes_bulk256() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let mut keys_created = Vec::new();

        let mut key_count_round1 = 0;
        loop {
            let result = app_session.aes_generate(
                AesKeySize::AesXtsBulk256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );

            if let Ok(key) = result {
                key_count_round1 += 1;
                keys_created.push(key);
            } else {
                break;
            }
        }

        println!(
            "Round 1: Vault exhausted after creating {} app only keys(Aes Bulk 256)",
            key_count_round1
        );

        assert!(key_count_round1 >= 1);

        // close session only deletes session only keys in the vault. So nop for
        // this test case wrt to key deletion.
        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        // Create a new session after key exhaustion and reclaiming of key vault
        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_ok(), "result {:?}", result);
        let app_session = result.unwrap();

        let mut key_count_round2 = 0;
        loop {
            let result = app_session.aes_generate(
                AesKeySize::AesXtsBulk256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );
            if result.is_ok() {
                key_count_round2 += 1;
            } else {
                break;
            }
        }

        println!(
            "Round 2: Vault exhausted after creating {} app only keys(Aes Bulk 256)",
            key_count_round2
        );

        // No new keys should be created since close session should not have deleted anything.
        assert_eq!(key_count_round2, 0);

        for key in keys_created {
            let result = app_session.delete_key(&key);
            assert!(result.is_ok());
        }

        let mut keys_created = Vec::new();

        let mut key_count_round3 = 0;
        loop {
            let result = app_session.aes_generate(
                AesKeySize::AesXtsBulk256,
                None,
                KeyProperties {
                    key_usage: KeyUsage::EncryptDecrypt,
                    key_availability: KeyAvailability::App,
                },
            );

            if let Ok(key) = result {
                key_count_round3 += 1;
                keys_created.push(key);
            } else {
                break;
            }
        }

        println!(
            "Round 3: Vault exhausted after creating {} app only keys(Aes Bulk 256)",
            key_count_round3
        );

        assert!(key_count_round3 >= 1);

        // check if we are able to recreate the same number of keys
        assert_eq!(key_count_round1, key_count_round3);

        // Delete all the keys again
        for key in keys_created {
            let result = app_session.delete_key(&key);
            assert!(result.is_ok());
        }
    });
}
