// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

fn test_thread_establish_credential(device_path: &str, barrier: Arc<Barrier>) {
    // Open device
    let result = HsmDevice::open(device_path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Wait for all threads to be ready to establish credentials
    barrier.wait();

    // Establish credential
    let api_rev = device.get_api_revision_range().max;
    let result = device.establish_credential(api_rev, TEST_CREDENTIALS);

    match result {
        Ok(()) => {}
        Err(HsmError::KeyNotFound) => {
            // When credentials are already established, the GetCredentialEncryptionKey is cleared
            // This is the expected error on mock Manticore
            // TODO: Need to check if consistent with firmware device behavior
        }
        _ => {
            assert!(result.is_ok(), "establish credential result {:?}", result);
        }
    }
}

#[test]
fn test_multithreaded_establish_credential() {
    let num_threads = 8;
    let device_path = get_device_path_helper();

    let mut threads = Vec::new();

    // Barrier to synchronize thread start
    let barrier = Arc::new(Barrier::new(num_threads));

    for _ in 1..=num_threads {
        let barrier_clone = Arc::clone(&barrier);
        let device_path_clone = device_path.clone();

        let thread = thread::spawn(move || {
            test_thread_establish_credential(&device_path_clone, barrier_clone)
        });

        threads.push(thread);
    }

    for thread in threads {
        thread.join().unwrap();
    }

    common_cleanup(&device_path);
}
