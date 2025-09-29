// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;
use mcr_api_resilient::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_establish_credential() {
    let device_path = get_device_path_helper();

    let result = HsmDevice::open(&device_path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Establish credential
    let api_rev = device.get_api_revision_range().max;
    let result = device.establish_credential(api_rev, TEST_CREDENTIALS);
    assert!(result.is_ok(), "establish credential result {:?}", result);

    // Simulate live migration
    simulate_live_migration_helper(&device_path);

    // Open session
    let result = device.open_session(device.get_api_revision_range().max, TEST_CREDENTIALS);
    assert!(result.is_ok(), "result {:?}", result);

    let _session = result.unwrap();

    common_cleanup(&device_path);
}
