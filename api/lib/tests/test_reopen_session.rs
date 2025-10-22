// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

#[cfg(feature = "mock")]
use std::sync::Arc;
#[cfg(feature = "mock")]
use std::sync::Barrier;
#[cfg(feature = "mock")]
use std::sync::RwLock;

#[cfg(feature = "mock")]
use mcr_api::HsmDevice;
#[cfg(feature = "mock")]
use mcr_api::*;
#[cfg(feature = "mock")]
use test_with_tracing::test;

#[cfg(feature = "mock")]
use crate::common::*;

/// Setup function that clears device without establish credentials
#[cfg(feature = "mock")]
pub fn setup(_device: &HsmDevice, path: &str) {
    let result = HsmDevice::open(path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Establish credential can only happen once so it could fail
    // in future instances so ignore error
    let api_rev = device.get_api_revision_range().max;
    let mut bk3 = [0u8; 48];
    use crypto::rand::rand_bytes;
    let _ = rand_bytes(&mut bk3);
    let masked_bk3 = device.init_bk3(api_rev, &bk3).unwrap();
    let resp = device.establish_credential(api_rev, TEST_APP_CREDENTIALS, masked_bk3, None, None);
    if let Err(resp) = resp {
        println!("establish credential failed with {}. Ignoring since establish credential can only be done once and may have happened before", resp);
    } else {
        println!("establish credential succeeded");
    }

    let mut app_session = common_open_app_session(&device);
    let result = app_session.clear_device();
    assert!(result.is_ok(), "clear_device result {:?}", result);
}

// Helper function for migration thread
#[cfg(feature = "mock")]
fn migration_thread_func(
    path: String,
    barrier: Arc<Barrier>,
    migration_lock: Arc<RwLock<bool>>,
    masked_bk3: Vec<u8>,
) -> bool {
    barrier.wait(); // Wait for both threads to be ready

    // Give operation thread time to start and do some work
    std::thread::sleep(std::time::Duration::from_millis(10));

    // Run 5 migration cycles
    for _i in 0..5 {
        {
            let _migration_lock = migration_lock.write().unwrap();
            let migration_result = common_simulate_lm_reestablish_cred(&path, masked_bk3.clone());
            if migration_result.is_err() {
                return false;
            }
        }

        // Wait before next migration to allow operations
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    true
}

// Helper function for operation thread
#[cfg(feature = "mock")]
fn operation_thread_func(
    session: Arc<HsmSession>,
    barrier: Arc<Barrier>,
    key_props: KeyProperties,
    migration_lock: Arc<RwLock<bool>>,
) -> bool {
    barrier.wait(); // Wait for both threads to be ready

    // Run 5 operation cycles - trying operations frequently to encounter migrations
    for _cycle in 0..5 {
        let mut retry_count = 0;
        let max_retries = 3;
        loop {
            let operation_result = {
                let _migration_lock = migration_lock.read().unwrap();
                session.aes_generate(AesKeySize::Aes256, None, key_props)
            };

            match operation_result {
                Ok(_) => {
                    break; // Success, move to next cycle
                }
                Err(HsmError::SessionNeedsRenegotiation) => {
                    // Reopen the session
                    let reopen_result = session.reopen(TEST_APP_CREDENTIALS);

                    match reopen_result {
                        Ok(_) => {
                            // Continue the loop to retry the key operation
                        }
                        Err(_e) => {
                            // Don't fail immediately, try a few more times
                            std::thread::sleep(std::time::Duration::from_millis(50));
                        }
                    }
                }
                Err(_e) => {
                    return false;
                }
            }

            retry_count += 1;
            if retry_count >= max_retries {
                return false;
            }

            // Short delay before retry
            std::thread::sleep(std::time::Duration::from_millis(30));
        }

        // Brief pause between cycles
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    true
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_basic() {
    api_test(setup, common_cleanup, |device, path| {
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(device, &bk3);

        println!("establish credential succeeded");
        let session = common_open_app_session(device);

        let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3);
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed"
        );

        // Verify session is invalidated and requires renegotiation
        let key_props = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        };

        let result = session.aes_generate(AesKeySize::Aes256, None, key_props);
        assert!(
            result.is_err(),
            "Key generation should fail after migration"
        );
        assert!(matches!(
            result.unwrap_err(),
            HsmError::SessionNeedsRenegotiation
        ));

        let reopen_result = session.reopen(TEST_APP_CREDENTIALS);
        assert!(
            reopen_result.is_ok(),
            "Session reopen should succeed: {:?}",
            reopen_result
        );

        let result = session.aes_generate(AesKeySize::Aes256, None, key_props);
        assert!(
            result.is_ok(),
            "Key generation should succeed after reopen: {:?}",
            result
        );
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_already_closed() {
    api_test(setup, common_cleanup, |device, path| {
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(device, &bk3);

        println!("establish credential succeeded");
        let mut session = common_open_app_session(device);

        let close_result = session.close_session();
        assert!(close_result.is_ok(), "Session close should succeed");

        let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3);
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed"
        );

        // Should fail when attempting to reopen a closed session
        let reopen_result = session.reopen(TEST_APP_CREDENTIALS);
        assert!(
            reopen_result.is_err(),
            "Reopen should fail on closed session"
        );

        match reopen_result.unwrap_err() {
            HsmError::SessionClosed => {
                // This is expected
            }
            other => panic!("Expected SessionClosed, got: {:?}", other),
        }
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_invalid_credentials() {
    api_test(setup, common_cleanup, |device, path| {
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(device, &bk3);

        println!("establish credential succeeded");
        let session = common_open_app_session(device);

        let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3);
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed"
        );

        let reopen_result = session.reopen(TEST_APP_CREDENTIALS_2);
        assert!(
            reopen_result.is_err(),
            "Reopen should fail with valid credentials"
        );
        assert!(matches!(
            reopen_result.unwrap_err(),
            HsmError::InvalidAppCredentials
        ));
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_multiple_operations() {
    api_test(setup, common_cleanup, |device, path| {
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(device, &bk3);

        println!("establish credential succeeded");
        let session = common_open_app_session(device);

        let key_props = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        };

        let key1_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
        assert!(key1_result.is_ok(), "First key generation should succeed");
        let _key1 = key1_result.unwrap();

        let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3);
        assert!(
            migration_result.is_ok(),
            "Migration simulation should succeed"
        );

        let reopen_result = session.reopen(TEST_APP_CREDENTIALS);
        assert!(reopen_result.is_ok(), "Session reopen should succeed");

        let key2_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
        assert!(
            key2_result.is_ok(),
            "Second key generation should succeed after reopen"
        );
        let key2 = key2_result.unwrap();

        // Verify encryption/decryption works with the new key
        let plaintext = vec![1u8; 128];
        let iv = [0x1u8; 16];

        let encrypt_result =
            session.aes_encrypt_decrypt(&key2, AesMode::Encrypt, plaintext.clone(), iv);
        assert!(
            encrypt_result.is_ok(),
            "Encryption should work after reopen"
        );

        let encrypted = encrypt_result.unwrap();
        assert_ne!(
            plaintext, encrypted.data,
            "Ciphertext should be different from plaintext"
        );

        let decrypt_result =
            session.aes_encrypt_decrypt(&key2, AesMode::Decrypt, encrypted.data, iv);
        assert!(
            decrypt_result.is_ok(),
            "Decryption should work after reopen"
        );

        let decrypted = decrypt_result.unwrap();
        assert_eq!(
            plaintext, decrypted.data,
            "Decrypted text should match original"
        );
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_without_migration() {
    api_test(common_setup, common_cleanup, |_device, _path| {
        let session = common_open_app_session(_device);

        // Should fail because reopen is only valid after migration
        let reopen_result = session.reopen(TEST_APP_CREDENTIALS);
        assert!(
            reopen_result.is_err(),
            "Reopen should fail when no live migration has occurred"
        );
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_multiple_rounds() {
    api_test(setup, common_cleanup, |device, path| {
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(device, &bk3);

        let key_props = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        };

        // Test multiple migration cycles
        for cycle in 0..3 {
            let mut session = common_open_app_session(device);

            let key_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
            assert!(
                key_result.is_ok(),
                "Cycle {}: Key generation should succeed before migration",
                cycle
            );

            let migration_result = common_simulate_lm_reestablish_cred(path, masked_bk3.clone());
            assert!(
                migration_result.is_ok(),
                "Cycle {}: Migration simulation should succeed",
                cycle
            );

            let invalid_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
            assert!(
                invalid_result.is_err(),
                "Cycle {}: Operations should fail after migration",
                cycle
            );
            assert!(matches!(
                invalid_result.unwrap_err(),
                HsmError::SessionNeedsRenegotiation
            ));

            let reopen_result = session.reopen(TEST_APP_CREDENTIALS);
            assert!(
                reopen_result.is_ok(),
                "Cycle {}: Session reopen should succeed",
                cycle
            );

            let final_key_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
            assert!(
                final_key_result.is_ok(),
                "Cycle {}: Key generation should succeed after reopen",
                cycle
            );

            // Close the session before next iteration
            let close_result = session.close_session();
            assert!(
                close_result.is_ok(),
                "Cycle {}: Session close should succeed",
                cycle
            );
        }
    });
}

#[test]
#[cfg(feature = "mock")]
fn test_reopen_session_concurrent_migration_and_operations() {
    use std::thread;

    api_test(setup, common_cleanup, |_device, path| {
        let key_props = KeyProperties {
            key_usage: KeyUsage::EncryptDecrypt,
            key_availability: KeyAvailability::App,
        };

        // Setup device for operations
        let device_op = HsmDevice::open(path).expect("Failed to open device1");
        let mut bk3 = [0u8; 48];
        use crypto::rand::rand_bytes;
        rand_bytes(&mut bk3).unwrap();

        let masked_bk3 = common_establish_credential(&device_op, &bk3);
        let session = common_open_app_session(&device_op);
        let session = Arc::new(session);

        // Barrier to synchronize thread startup
        let barrier = Arc::new(Barrier::new(2));
        // RW lock to synchronize migration state
        let migration_lock = Arc::new(RwLock::new(false));

        // Thread 1: Perform live migration using helper function
        let migration_thread = thread::spawn({
            let path = path.to_string();
            let barrier = Arc::clone(&barrier);
            let migration_lock = Arc::clone(&migration_lock);
            move || migration_thread_func(path, barrier, migration_lock, masked_bk3.clone())
        });

        // Thread 2: Perform key operations, handle SessionNeedsRenegotiation, and retry using helper function
        let operation_thread = thread::spawn({
            let session = Arc::clone(&session);
            let barrier = Arc::clone(&barrier);
            let migration_lock = Arc::clone(&migration_lock);
            move || operation_thread_func(session, barrier, key_props, migration_lock)
        });

        // Wait for both threads to complete
        let migration_success = migration_thread.join().expect("Migration thread panicked");
        let operation_success = operation_thread.join().expect("Operation thread panicked");

        assert!(migration_success, "Migration should succeed");
        assert!(
            operation_success,
            "Key operation should eventually succeed after reopen"
        );

        // Verify the session is still functional after all the concurrent operations
        // After migration, we might need to reopen the session
        let final_key_result = session.aes_generate(AesKeySize::Aes256, None, key_props);
        match final_key_result {
            Ok(_) => {
                // Key generation succeeded, session is still valid
            }
            Err(HsmError::SessionNeedsRenegotiation) => {
                session
                    .reopen(TEST_APP_CREDENTIALS)
                    .expect("Session reopen should succeed");
            }
            Err(e) => {
                panic!("Final key generation failed with unexpected error: {:?}", e);
            }
        }
    });
}
