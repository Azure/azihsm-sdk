// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_resilient_session_open() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    // First, create a session key to verify the session is working
    let _first_key = generate_session_aes_key(&session, "first aes_generate failed");

    simulate_live_migration_helper(&device_path);

    // Add another session key to the session after migration
    let _second_key =
        generate_session_aes_key(&session, "second aes_generate after migration failed");
}

#[test]
#[cfg(feature = "mock")]
fn test_close_session_after_live_migration() {
    let device_path = get_device_path_helper();
    let (_device, mut session, _api_rev) = setup_device_and_session(&device_path);

    simulate_live_migration_helper(&device_path);

    let result = session.close_session();
    assert!(result.is_ok(), "close_session result {:?}", result);
}

#[test]
fn test_session_survives_multiple_live_migrations() {
    let device_path = get_device_path_helper();
    let (_device, session, _api_rev) = setup_device_and_session(&device_path);

    // Create initial session key
    let _initial_key = generate_session_aes_key(&session, "initial aes_generate failed");

    // First live migration
    simulate_live_migration_helper(&device_path);
    let _key_after_1st =
        generate_session_aes_key(&session, "aes_generate after 1st migration failed");

    // Second live migration
    simulate_live_migration_helper(&device_path);
    let _key_after_2nd =
        generate_session_aes_key(&session, "aes_generate after 2nd migration failed");

    // Third live migration
    simulate_live_migration_helper(&device_path);
    let _key_after_3rd =
        generate_session_aes_key(&session, "aes_generate after 3rd migration failed");
}

#[test]
fn test_multiple_device_instances_with_live_migration() {
    let device_path = get_device_path_helper();

    // Open two resilient Device instances
    let (dev1, api_rev) = setup_device(&device_path);
    let dev2 = HsmDevice::open(&device_path).expect("Failed to open second HSM device");

    let session1 = dev1
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev1");

    simulate_live_migration_helper(&device_path);

    let _session1_key =
        generate_session_aes_key(&session1, "session1 aes_generate after migration failed");

    // Open a new session on dev2 and add session key works
    let session2 = dev2
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session on dev2");

    let _session2_key = generate_session_aes_key(&session2, "session2 aes_generate failed");

    simulate_live_migration_helper(&device_path);

    // Add session keys for both sessions and still work
    let _session1_key2 = generate_session_aes_key(
        &session1,
        "session1 aes_generate after 2nd migration failed",
    );
    let _session2_key2 = generate_session_aes_key(
        &session2,
        "session2 aes_generate after 2nd migration failed",
    );
}
