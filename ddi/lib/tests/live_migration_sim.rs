// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::sync::Arc;
use std::sync::Barrier;
use std::thread;
use std::time::Duration;

use mcr_ddi::Ddi;
use mcr_ddi::DdiDev;
use mcr_ddi::DdiError;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::DdiAesKeySize;
use mcr_ddi_types::DdiApiRev;
use mcr_ddi_types::DdiKeyAvailability;
use mcr_ddi_types::DdiKeyUsage;
use mcr_ddi_types::DdiStatus;
use parking_lot::RwLock;
use test_with_tracing::test;
use tracing::info;

use crate::common::*;

/// Information needed for thread-safe session reopening operations
struct ThreadSessionInfo {
    dev: <DdiTest as Ddi>::Dev,
    session_id: u16,
    session_bmk: Vec<u8>,
    credential_lock: Arc<RwLock<()>>,
    thread_id: usize,
}

impl ThreadSessionInfo {
    fn new(
        ddi: &DdiTest,
        dev_path: &str,
        credential_lock: &Arc<RwLock<()>>,
        thread_id: usize,
    ) -> Result<Self, DdiError> {
        let mut dev = ddi.open_dev(dev_path).unwrap();
        set_device_kind(&mut dev);

        let _lock = credential_lock.write();
        info!(
            "Thread {}: Generating encrypted credentials for session open",
            thread_id
        );

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        info!(
            "Thread {}: Generated encrypted credentials, attempting to open session",
            thread_id
        );

        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )?;

        let session_id = resp.hdr.sess_id.unwrap();
        let session_bmk = resp.data.bmk_session.as_slice().to_vec();
        info!(
            "Thread {}: Successfully opened session with ID {}",
            thread_id, session_id
        );

        // Construct and return the instance with the actual session ID
        Ok(Self {
            dev,
            session_id,
            credential_lock: Arc::clone(credential_lock),
            thread_id,
            session_bmk,
        })
    }

    /// Atomically encrypt user credentials and reopen a session with retry logic
    /// This is needed as each session would reset the nonce in Mock vault implementation
    /// # Returns
    /// * `Ok(DdiReopenSessionCmdResp)` - Successful session reopen response
    /// * `Err(String)` - Error message after all retry attempts failed
    fn encrypt_userid_pin_and_reopen_session_with_retry(
        &self,
        session_bmk: &[u8],
    ) -> Result<mcr_ddi_types::DdiReopenSessionCmdResp, String> {
        const MAX_RETRIES: usize = 5;
        let mut retry_count = 0;

        loop {
            let reopen_result = {
                let _lock = self.credential_lock.write();
                info!(
                    "Thread {}: Generating encrypted credentials for session reopen",
                    self.thread_id
                );

                // Atomic encrypt + reopen operation
                let encrypt_result = encrypt_userid_pin_for_open_session_no_unwrap(
                    &self.dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                match encrypt_result {
                    Ok((new_encrypted_credential, new_pub_key)) => {
                        info!(
                            "Thread {}: Generated encrypted credentials, attempting reopen",
                            self.thread_id
                        );
                        helper_reopen_session(
                            &self.dev,
                            self.session_id,
                            Some(DdiApiRev { major: 1, minor: 0 }),
                            new_encrypted_credential,
                            new_pub_key,
                            MborByteArray::from_slice(session_bmk)
                                .expect("Failed to create empty BMK array"),
                        )
                    }
                    Err(e) => {
                        info!(
                            "Thread {}: Failed to generate encrypted credentials: {}",
                            self.thread_id, e
                        );
                        Err(DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation))
                    }
                }
            };

            match reopen_result {
                Ok(reopen_resp) => {
                    let reopened_session_id = reopen_resp.data.sess_id;
                    info!(
                        "Thread {}: Successfully reopened session with ID {} on attempt {}",
                        self.thread_id,
                        reopened_session_id,
                        retry_count + 1
                    );
                    return Ok(reopen_resp);
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= MAX_RETRIES {
                        return Err(format!(
                            "Thread {}: Failed to reopen session after {} attempts: {}",
                            self.thread_id, MAX_RETRIES, e
                        ));
                    }
                    info!(
                        "Thread {}: Reopen attempt {} failed: {}, retrying in 100ms",
                        self.thread_id, retry_count, e
                    );
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

// Just simulate live migration
#[test]
fn test_live_migration_sim_minimum() {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();

    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    for dev_info in dev_infos.iter() {
        let mut dev = ddi.open_dev(&dev_info.path).unwrap();
        set_device_kind(&mut dev);

        dev.simulate_nssr_after_lm().unwrap()
    }
}

// Simulate a live migration of the AziHSM partition for current VM (VF)
#[test]
fn test_live_migration_sim_basic() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id = setup_res.session_id;

            // Add an AES key to the session
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes256,
                Some(0x1234),
                key_props,
            );
            assert!(resp.is_ok(), "Failed to generate AES key: {:?}", resp);

            // Simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Add another key, should get an error of SessionNeedsRenegotiation.
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(0x5678),
                key_props,
            );
            assert!(resp.is_err(), "Should fail after migration");
            assert!(
                matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation)
                ),
                "Should get SessionNeedsRenegotiation error."
            );

            let _partition_bmk = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
            );

            // Generate fresh encrypted credentials for the new device handle
            let (new_encrypted_credential, new_pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let reopen_resp = helper_reopen_session(
                dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_encrypted_credential,
                new_pub_key,
                MborByteArray::from_slice(setup_res.session_bmk.as_slice())
                    .expect("Failed to create BMK array"),
            );
            assert!(
                reopen_resp.is_ok(),
                "Reopen session should succeed: {:?}",
                reopen_resp
            );
            let reopened_session = reopen_resp.unwrap();
            assert_eq!(
                reopened_session.data.sess_id, session_id,
                "Reopened session should have same ID"
            );

            // Add a key to session after reopen - should work
            // Use the same device handle for this operation
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes192,
                Some(0x9ABC),
                key_props,
            );
            assert!(resp.is_ok(), "Should work after session reopen: {:?}", resp);
        },
    );
}
// Test: get sealed BK3, simulate live migration, set sealed BK3
#[cfg(feature = "mock")]
#[test]
fn test_live_migration_sealed_bk3() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let sealed_bk3 = [0xAB; 256];
            let res = helper_set_sealed_bk3(dev, sealed_bk3.to_vec());
            assert!(res.is_ok(), "Failed to set initial sealed BK3: {:?}", res);
            let sealed_bk3_before = helper_get_sealed_bk3(dev);
            assert!(
                sealed_bk3_before.is_ok(),
                "Failed to get sealed BK3 before migration: {:?}",
                sealed_bk3_before
            );
            let sealed_bk3_data = sealed_bk3_before.unwrap();
            info!(
                "Retrieved sealed BK3 data: {} bytes",
                sealed_bk3_data.data.sealed_bk3.len()
            );

            let migration_result = dev.simulate_nssr_after_lm();
            assert!(
                migration_result.is_ok(),
                "Migration simulation should succeed: {:?}",
                migration_result
            );
            info!("Live migration simulation completed successfully");

            let set_result = helper_set_sealed_bk3(
                dev,
                sealed_bk3_data.data.sealed_bk3.clone().as_slice().to_vec(),
            );
            assert!(
                set_result.is_err(),
                "Expected failure when setting sealed BK3 after migration: {:?}",
                set_result
            );
            assert!(
                matches!(
                    set_result.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::KeyTagAlreadyExists)
                ),
                "Should get KeyTagAlreadyExists error."
            );
            info!("Successfully got expected KeyTagAlreadyExists error after migration");

            // Verify: Get sealed BK3 again to confirm it was migrated correctly
            let sealed_bk3_after = helper_get_sealed_bk3(dev);
            assert!(
                sealed_bk3_after.is_ok(),
                "Failed to get sealed BK3 after setting: {:?}",
                sealed_bk3_after
            );
            let sealed_bk3_after_data = sealed_bk3_after.unwrap();

            assert_eq!(
                sealed_bk3_data.data.sealed_bk3, sealed_bk3_after_data.data.sealed_bk3,
                "Sealed BK3 data should be identical before and after migration"
            );
            info!("Verified sealed BK3 data integrity across migration");
        },
    );
}

// Test: open two sessions, sim LM, both sessions can be reopened
#[test]
fn test_live_migration_two_sessions() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            // Create session 1 on first device handle
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id1 = setup_res.session_id;
            let session_bmk1 = setup_res.session_bmk;
            let session_seed1 = setup_res.random_seed;

            // Create a new device handle for session 2
            let mut dev2 = ddi.open_dev(path).unwrap();
            set_device_kind(&mut dev2);

            let (encrypted_credential2, pub_key2) = encrypt_userid_pin_for_open_session(
                &dev2,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp2 = helper_open_session(
                &dev2,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential2,
                pub_key2,
            );
            assert!(resp2.is_ok(), "Failed to open second session: {:?}", resp2);
            let resp2 = resp2.unwrap();
            let session_id2 = resp2.hdr.sess_id.unwrap();
            let session_bmk2 = resp2.data.bmk_session.as_slice().to_vec();
            let session_seed2 = TEST_SESSION_SEED;

            // Simulate live migration with original device handle
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _partition_bmk = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
            );

            // Generate fresh encrypted credentials for session 1
            let (new_encrypted_credential1, new_pub_key1) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                session_seed1,
            );

            // Reopen session 1
            let reopen_resp1 = helper_reopen_session(
                dev,
                session_id1,
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_encrypted_credential1,
                new_pub_key1,
                MborByteArray::from_slice(session_bmk1.as_slice())
                    .expect("Failed to create empty BMK array"),
            );
            assert!(
                reopen_resp1.is_ok(),
                "Reopen session 1 should succeed: {:?}",
                reopen_resp1
            );

            // Generate fresh encrypted credentials for session 2
            let (new_encrypted_credential2, new_pub_key2) = encrypt_userid_pin_for_open_session(
                &dev2,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                session_seed2,
            );

            // Reopen session 2
            let reopen_resp2 = helper_reopen_session(
                &dev2,
                session_id2,
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_encrypted_credential2,
                new_pub_key2,
                MborByteArray::from_slice(session_bmk2.as_slice())
                    .expect("Failed to create empty BMK array"),
            );
            assert!(
                reopen_resp2.is_ok(),
                "Reopen session 2 should succeed: {:?}",
                reopen_resp2
            );

            // Verify both sessions have the same IDs
            assert_eq!(
                reopen_resp1.unwrap().data.sess_id,
                session_id1,
                "Reopened session 1 should have same ID"
            );
            assert_eq!(
                reopen_resp2.unwrap().data.sess_id,
                session_id2,
                "Reopened session 2 should have same ID"
            );
        },
    );
}

// Test: open ZERO sessions, sim LM, reopen session fails
#[test]
fn test_live_migration_zero_sessions() {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();

    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    for dev_info in dev_infos.iter() {
        let mut dev = ddi.open_dev(&dev_info.path).unwrap();
        set_device_kind(&mut dev);

        // Don't open any sessions, just establish credentials
        let _ = helper_common_establish_credential_no_unwrap(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

        // Simulate live migration
        let result = dev.simulate_nssr_after_lm();
        assert!(
            result.is_ok(),
            "Migration simulation should succeed: {:?}",
            result
        );

        let _ = helper_common_establish_credential_no_unwrap(&mut dev, TEST_CRED_ID, TEST_CRED_PIN);

        // Generate fresh encrypted credentials
        let (new_encrypted_credential, new_pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        // Try to reopen a non-existent session (session ID 1)
        let reopen_resp = helper_reopen_session(
            &dev,
            1,
            Some(DdiApiRev { major: 1, minor: 0 }),
            new_encrypted_credential,
            new_pub_key,
            MborByteArray::from_slice(&[]).expect("Failed to create empty BMK array"),
        );
        assert!(
            reopen_resp.is_err(),
            "Reopen should fail when no session exists: {:?}",
            reopen_resp
        );
    }
}

// Test: open session, DON'T sim LM, reopen session fails
#[test]
fn test_reopen_no_live_migration_sim() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            // Initialize and open session
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id = setup_res.session_id;

            // Don't simulate live migration

            let _ = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);

            // Generate fresh encrypted credentials
            let (new_encrypted_credential, new_pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Try to reopen session without migration
            let reopen_resp = helper_reopen_session(
                dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_encrypted_credential,
                new_pub_key,
                MborByteArray::from_slice(setup_res.session_bmk.as_slice())
                    .expect("Failed to create empty BMK array"),
            );
            assert!(
                reopen_resp.is_err(),
                "Reopen should fail without migration: {:?}",
                reopen_resp
            );
        },
    );
}

// Test: open session, sim LM, close session is successful or reopen then close
#[test]
fn test_close_session_after_live_migration_sim() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id = setup_res.session_id;

            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // After live migration, try to close the session
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );

            // If close_session succeeds after LM, the test passes
            if resp.is_ok() {
                return;
            }

            // Otherwise, verify it fails with SessionNeedsRenegotiation and perform reopen
            assert!(
                matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation)
                ),
                "Expected SessionNeedsRenegotiation error after LM"
            );

            // Re-establish credentials after live migration
            let _partition_bmk = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
            );

            // Generate fresh encrypted credentials for reopening the session
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                MborByteArray::from_slice(setup_res.session_bmk.as_slice())
                    .expect("Failed to create BMK array"),
            );
            assert!(resp.is_ok(), "Reopen session should succeed: {:?}", resp);

            // Now close_session should succeed
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(
                resp.is_ok(),
                "Close session should succeed after reopen: {:?}",
                resp
            );
        },
    );
}

// Test: open session, sim LM, reopen session on new device handle fails
#[test]
fn test_live_migration_reopen_new_device_handle() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            // Simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Create a new device handle
            let mut new_dev = ddi.open_dev(path).unwrap();
            set_device_kind(&mut new_dev);

            let _ = helper_common_establish_credential_no_unwrap(
                &mut new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
            );

            // Generate fresh encrypted credentials for the new device handle
            let (new_encrypted_credential, new_pub_key) = encrypt_userid_pin_for_open_session(
                &new_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            // Try to reopen session on new device handle - should fail
            let reopen_resp = helper_reopen_session(
                &new_dev,
                session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_encrypted_credential,
                new_pub_key,
                MborByteArray::from_slice(&[]).expect("Failed to create empty BMK array"),
            );
            assert!(
                reopen_resp.is_err(),
                "Reopen should fail on new device handle: {:?}",
                reopen_resp
            );
        },
    );
}

// Test: open session, repeat live migration and reopen 5 times
#[test]
fn test_live_migration_repeated_cycles() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _| {
            // Initialize and open session
            let setup_res = common_setup_for_lm(dev, ddi, path);
            let session_id = setup_res.session_id;
            let session_bmk = setup_res.session_bmk;
            let session_seed = setup_res.random_seed;

            // Repeat the live migration and reopen cycle 5 times
            for i in 1..=5 {
                info!("Starting live migration cycle {}", i);

                // Simulate live migration
                let result = dev.simulate_nssr_after_lm();
                assert!(
                    result.is_ok(),
                    "Migration simulation should succeed on cycle {}: {:?}",
                    i,
                    result
                );

                // Re-establish credentials after migration
                let _partition_bmk = helper_common_establish_credential_with_bmk(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    setup_res.masked_bk3,
                    setup_res.partition_bmk,
                    MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
                );

                // Generate fresh encrypted credentials for reopening
                let (new_encrypted_credential, new_pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    session_seed,
                );

                // Reopen the same session
                let reopen_resp = helper_reopen_session(
                    dev,
                    session_id,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    new_encrypted_credential,
                    new_pub_key,
                    MborByteArray::from_slice(session_bmk.as_slice())
                        .expect("Failed to create empty BMK array"),
                );
                assert!(
                    reopen_resp.is_ok(),
                    "Reopen session should succeed on cycle {}: {:?}",
                    i,
                    reopen_resp
                );

                let reopened_session = reopen_resp.unwrap();
                assert_eq!(
                    reopened_session.data.sess_id, session_id,
                    "Reopened session should have same ID on cycle {}",
                    i
                );

                // Verify the session is functional by adding a key
                let key_props =
                    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
                let resp = helper_aes_generate(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiAesKeySize::Aes256,
                    Some(0x1000 + i as u16), // Use different key IDs for each cycle
                    key_props,
                );
                assert!(
                    resp.is_ok(),
                    "Should be able to generate key after reopen on cycle {}: {:?}",
                    i,
                    resp
                );

                info!("Completed live migration cycle {}", i);
            }
        },
    );
}

// Test: 6 threads - one doing live migrations, adding session keys in other 5 threads
#[test]
fn test_live_migration_concurrent_shared_session() {
    let ddi = Arc::new(DdiTest::default());
    let dev_infos = ddi.dev_info_list();

    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let dev_info = &dev_infos[0];

    // Setup: Create device and establish initial session
    let mut dev = ddi.open_dev(&dev_info.path).unwrap();
    set_device_kind(&mut dev);

    // Initialize and open session
    let setup_res = common_setup_for_lm(&mut dev, &ddi, &dev_info.path);
    let session_id = setup_res.session_id;
    info!("Initial session opened with ID: {}", session_id);

    // Wrap device in Arc<RwLock<>> for thread safety
    let shared_dev = Arc::new(RwLock::new(dev));

    // Barrier to synchronize thread start (1 migration + 5 key threads)
    let barrier = Arc::new(Barrier::new(6));

    let dev_clone = Arc::clone(&shared_dev);
    let barrier_clone = Arc::clone(&barrier);

    // Thread 1: Live migration and session reopen thread
    let migration_thread = thread::spawn(move || -> Result<(), String> {
        barrier_clone.wait(); // Wait for both threads to be ready
        info!("Migration thread started");

        for i in 1..=20 {
            info!("Migration thread: Starting cycle {}", i);

            // Simulate live migration
            {
                let dev_guard = dev_clone.write();
                let result = dev_guard.simulate_nssr_after_lm();
                if result.is_err() {
                    return Err(format!("Migration failed on cycle {}: {:?}", i, result));
                }
                info!("Migration thread: Completed migration {}", i);
            }

            // Brief pause to let key thread potentially encounter the migration
            thread::sleep(Duration::from_millis(50));

            // Re-establish credentials and reopen session using the SAME device handle
            {
                let mut dev_guard = dev_clone.write();

                info!("Migration thread: Attempting credential re-establishment on same device handle");
                let _partition_bmk = helper_common_establish_credential_with_bmk(
                    &mut dev_guard,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    setup_res.masked_bk3,
                    setup_res.partition_bmk,
                    MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
                );

                // Generate fresh encrypted credentials for reopening
                let encrypt_result = encrypt_userid_pin_for_open_session_no_unwrap(
                    &dev_guard,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    setup_res.random_seed,
                );

                if let Ok((new_encrypted_credential, new_pub_key)) = encrypt_result {
                    // Reopen the same session on the main device
                    let reopen_resp = helper_reopen_session(
                        &dev_guard,
                        session_id,
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        new_encrypted_credential,
                        new_pub_key,
                        MborByteArray::from_slice(setup_res.session_bmk.as_slice())
                            .expect("Failed to create BMK array"),
                    );

                    if let Ok(reopen_result) = reopen_resp {
                        let reopened_session_id = reopen_result.data.sess_id;
                        if reopened_session_id != session_id {
                            return Err(format!(
                                "Reopened session ID {} doesn't match original {}",
                                reopened_session_id, session_id
                            ));
                        }
                        info!("Migration thread: Successfully reopened session {}", i);
                    } else {
                        return Err(format!(
                            "Failed to reopen session on cycle {}: {:?}",
                            i, reopen_resp
                        ));
                    }
                } else {
                    return Err(format!(
                        "Failed to generate credentials on cycle {}: {:?}",
                        i, encrypt_result
                    ));
                }
            }

            thread::sleep(Duration::from_millis(100)); // Brief pause between cycles
        }

        info!("Migration thread completed all 20 cycles");
        Ok(())
    });

    // Create 5 key operation threads
    let mut key_threads = Vec::new();

    for thread_id in 1..=5 {
        let dev_clone = Arc::clone(&shared_dev);
        let barrier_clone = Arc::clone(&barrier);

        let key_thread = thread::spawn(move || -> Result<(), String> {
            barrier_clone.wait(); // Wait for all threads to be ready
            info!("Key thread {} started", thread_id);

            for i in 1..=20 {
                info!("Key thread {}: Starting key operation {}", thread_id, i);

                // Try to add a session key
                let key_props =
                    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
                let key_result = {
                    let dev_guard = dev_clone.read();
                    helper_aes_generate(
                        &dev_guard,
                        Some(session_id),
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        DdiAesKeySize::Aes256,
                        Some(0x4000 + (thread_id * 1000) + i as u16), // Unique key IDs per thread
                        key_props,
                    )
                };

                match key_result {
                    Ok(_) => {
                        info!("Key thread {}: Successfully added key {}", thread_id, i);
                    }
                    Err(DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation)) => {
                        info!(
                            "Key thread {}: Got expected SessionNeedsRenegotiation on attempt {}",
                            thread_id, i
                        );
                        // This is expected when migration happens, continue
                    }
                    Err(e) => {
                        // Any other error should fail the test
                        return Err(format!(
                            "Key thread {}: Unexpected error on attempt {}: {:?}",
                            thread_id, i, e
                        ));
                    }
                }

                thread::sleep(Duration::from_millis(80)); // Brief pause between key operations
            }

            info!("Key thread {} completed all 20 cycles", thread_id);
            Ok(())
        });

        key_threads.push(key_thread);
    }

    // Wait for migration thread to complete
    let migration_result = migration_thread.join().unwrap();

    // Wait for all key threads to complete
    let mut key_results = Vec::new();
    for (i, key_thread) in key_threads.into_iter().enumerate() {
        let result = key_thread.join().unwrap();
        key_results.push((i + 1, result));
    }

    // Check results
    assert!(
        migration_result.is_ok(),
        "Migration thread failed: {:?}",
        migration_result
    );

    for (thread_id, key_result) in key_results {
        assert!(
            key_result.is_ok(),
            "Key thread {} failed: {:?}",
            thread_id,
            key_result
        );
    }

    info!("Both threads completed successfully with shared session");
}

// Test: multiple threads each with their own device handle and session
#[test]
fn test_live_migration_concurrent_separate_sessions() {
    let ddi = Arc::new(DdiTest::default());
    let dev_infos = ddi.dev_info_list();

    if dev_infos.is_empty() {
        panic!("No devices found");
    }

    let dev_info = &dev_infos[0];

    // Create a main device handle for credential establishment
    let mut main_dev = ddi.open_dev(&dev_info.path).unwrap();
    set_device_kind(&mut main_dev);

    // Setup for live migration
    let setup_res = common_setup_for_lm(&mut main_dev, &ddi, &dev_info.path);

    // Create a mutex to serialize credential generation to prevent nonce conflicts
    let credential_lock = Arc::new(RwLock::new(()));

    // Create all sessions in main thread in serialized way
    let mut session_infos = Vec::new();
    const NUM_SESSION_THREADS: usize = 5;

    for thread_id in 2..=(1 + NUM_SESSION_THREADS) {
        // Create ThreadSessionInfo instance which automatically opens a session and device
        let thread_session_info =
            ThreadSessionInfo::new(&ddi, &dev_info.path, &credential_lock, thread_id);

        match thread_session_info {
            Ok(info) => {
                println!(
                    "Main thread: Created session {} for thread {}",
                    info.session_id, info.thread_id
                );
                session_infos.push(info);
            }
            Err(e) => {
                panic!(
                    "Main thread: Failed to create session for thread {}: {:?}",
                    thread_id, e
                );
            }
        }
    }

    // Function to handle session management operations with separate device and session
    fn session_management_worker_with_own_session(
        thread_session_info: ThreadSessionInfo,
        barrier: Arc<Barrier>,
    ) -> Result<(), String> {
        let thread_id = thread_session_info.thread_id;
        let session_id = thread_session_info.session_id;

        info!(
            "Thread {}: Using pre-created device handle with session ID {}",
            thread_id, session_id
        );

        // Add a small delay before barrier to help with timing
        thread::sleep(Duration::from_millis(50));

        info!("Thread {}: About to wait at barrier", thread_id);
        barrier.wait(); // Wait for all threads to be ready
        info!("Thread {}: Passed barrier, starting main loop", thread_id);

        let mut key_counter = 0u16;
        let mut loop_count = 0;
        const MAX_LOOPS: usize = 20; // Prevent infinite loops

        while loop_count < MAX_LOOPS {
            loop_count += 1;
            key_counter += 1;

            info!(
                "Thread {}: Attempting to add session key (attempt {})",
                thread_id, loop_count
            );

            // Step 2: Try to add a session key (use read lock for concurrent access)
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
            let key_result = {
                let _read_lock = thread_session_info.credential_lock.read();
                helper_aes_generate(
                    &thread_session_info.dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiAesKeySize::Aes256,
                    Some(0x3000 + (thread_id as u16 * 1000) + key_counter), // Unique key IDs per thread
                    key_props,
                )
            };

            match key_result {
                Ok(_) => {
                    info!("Thread {}: Successfully added session key", thread_id);
                    thread::sleep(Duration::from_millis(100)); // Brief pause before next attempt
                }
                Err(DdiError::DdiStatus(DdiStatus::SessionNeedsRenegotiation)) => {
                    info!(
                        "Thread {}: Got SessionNeedsRenegotiation, attempting to reopen session",
                        thread_id
                    );

                    // Give migration thread time to re-establish credentials
                    thread::sleep(Duration::from_millis(10));

                    // Use the ThreadSessionInfo instance directly for session reopening
                    match thread_session_info.encrypt_userid_pin_and_reopen_session_with_retry(
                        &thread_session_info.session_bmk,
                    ) {
                        Ok(reopen_resp) => {
                            let reopened_session_id = reopen_resp.data.sess_id;
                            info!(
                                "Thread {}: Successfully reopened session with ID {}",
                                thread_id, reopened_session_id
                            );
                            // Continue with the main loop after successful reopen
                        }
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
                Err(e) => {
                    // Any other error, fail the test
                    return Err(format!(
                        "Thread {}: Unexpected error while adding session key: {:?}",
                        thread_id, e
                    ));
                }
            }
        }

        info!("Thread {}: Completed {} loops", thread_id, loop_count);
        Ok(())
    }

    // Create a single migration device for triggering migrations
    let mut migration_dev = ddi.open_dev(&dev_info.path).unwrap();
    set_device_kind(&mut migration_dev);

    let barrier = Arc::new(Barrier::new(1 + NUM_SESSION_THREADS)); // 1 migration thread + session threads

    let barrier_clone = Arc::clone(&barrier);
    let credential_lock_clone = Arc::clone(&credential_lock);

    // Thread 1: Live migration loop
    let migration_thread = thread::spawn(move || {
        info!("Migration Thread: About to wait at barrier");
        barrier_clone.wait(); // Wait for all threads to be ready
        info!("Migration Thread: Passed barrier, starting migrations");

        for i in 1..=5 {
            info!("Migration Thread: Starting live migration cycle {}", i);

            {
                let _write_lock = credential_lock_clone.write();

                let result = migration_dev.simulate_nssr_after_lm();
                if result.is_err() {
                    eprintln!(
                        "Migration Thread: Migration simulation failed on cycle {}: {:?}",
                        i, result
                    );
                    return Err(format!("Migration failed on cycle {}: {:?}", i, result));
                }

                // Re-establish credentials once for all threads
                info!(
                    "Migration Thread: Re-establishing credentials after migration {}",
                    i
                );
                let _partition_bmk = helper_common_establish_credential_with_bmk(
                    &mut migration_dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    setup_res.masked_bk3,
                    setup_res.partition_bmk,
                    MborByteArray::from_slice(&[]).expect("Failed to create empty Mbor array"),
                );
                info!(
                    "Migration Thread: Successfully re-established credentials after migration {}",
                    i
                );
            }

            info!("Migration Thread: Completed live migration cycle {}", i);
            thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    });

    // Create 5 session management threads, each with their own device and session
    let mut session_threads = Vec::new();
    for thread_session_info in session_infos {
        let barrier_clone = Arc::clone(&barrier);

        println!(
            "Creating thread {} with session ID {}",
            thread_session_info.thread_id, thread_session_info.session_id
        );
        let session_thread = thread::spawn(move || {
            println!(
                "Thread {} started with session ID {}",
                thread_session_info.thread_id, thread_session_info.session_id
            );
            println!(
                "Thread {} using owned device handle",
                thread_session_info.thread_id
            );

            session_management_worker_with_own_session(thread_session_info, barrier_clone)
        });
        session_threads.push(session_thread);
    }

    // Wait for migration thread to complete
    let migration_result = migration_thread.join().unwrap();

    // Wait for all session threads to complete
    let mut all_session_results = Vec::new();
    for (i, session_thread) in session_threads.into_iter().enumerate() {
        let result = session_thread.join().unwrap();
        all_session_results.push((i + 2, result)); // Thread IDs start from 2
    }

    // Check results
    assert!(
        migration_result.is_ok(),
        "Migration thread failed: {:?}",
        migration_result
    );

    for (thread_id, session_result) in all_session_results {
        assert!(
            session_result.is_ok(),
            "Session thread {} failed: {:?}",
            thread_id,
            session_result
        );
    }

    println!("All threads completed successfully - each with separate sessions");
}

// Run only on mock device
// Check the hash before and after live migration
// This only applies for mock. In firmware scenario, certificate(s)
// will only change if there's an impactless update or similar.
#[cfg(feature = "mock")]
#[test]
fn test_get_cert_chain_info_during_live_migration() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            // Call GetCertChainInfo before migration
            let (_cert_count, hash1) = helper_get_cert_chain_info_data(dev);

            // Simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Call GetCertChainInfo after migration
            let (_cert_count, hash2) = helper_get_cert_chain_info_data(dev);

            // Two hash should be different
            assert_ne!(hash1, hash2);
        },
    );
}

// Run only on mock device
// Calculate the hash before and after live migration
// This only applies for mock. In firmware scenario, certificate(s)
// will only change if there's an impactless update or similar.
#[cfg(feature = "mock")]
#[test]
fn test_get_cert_hash_during_live_migration() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            // Call GetCertChainInfo before migration
            let (cert_count, hash1) = helper_get_cert_chain_info_data(dev);
            assert!(
                cert_count == 1,
                "Virtual device should have 1 cert, got {}",
                cert_count
            );

            // Simulate live migration
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Get the cert
            let result = helper_get_certificate(dev, 0);
            assert!(
                result.is_ok(),
                "GetCertificate should succeed: {:?}",
                result
            );
            let cert = result.unwrap().data.certificate;

            let result = crypto::sha::sha(crypto::sha::HashAlgorithm::Sha256, cert.as_slice());
            assert!(result.is_ok(), "SHA256 calculation should succeed");
            let hash2 = result.unwrap();

            // Compute the hash
            assert_ne!(
                hash1.to_vec(),
                hash2,
                "Hash before and after migration should NOT match"
            )
        },
    );
}
