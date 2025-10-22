// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

fn test_thread_open_session(device_path: &str, barrier: Arc<Barrier>) -> HsmSession {
    // Open device
    let result = HsmDevice::open(device_path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Wait for all threads to be ready to call open session
    barrier.wait();

    // Open session
    let api_rev = device.get_api_revision_range().max;
    let result = device.open_session(api_rev, TEST_CREDENTIALS);

    assert!(result.is_ok(), "open session result {:?}", result);
    result.unwrap()
}

#[test]
fn test_multithreaded_open_session() {
    let num_threads = 8;
    let device_path = get_device_path_helper();

    // Open device
    let result = HsmDevice::open(&device_path);
    assert!(result.is_ok(), "result {:?}", result);

    let mut threads = Vec::new();

    // Barrier to synchronize thread start
    let barrier = Arc::new(Barrier::new(num_threads));

    for _ in 1..=num_threads {
        let barrier_clone = Arc::clone(&barrier);
        let device_path_clone = device_path.clone();

        let thread =
            thread::spawn(move || test_thread_open_session(&device_path_clone, barrier_clone));

        threads.push(thread);
    }

    for thread in threads {
        thread.join().unwrap();
    }
}
