// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;
use uuid::Uuid;

use crate::common::*;

#[test]
fn test_change_pin() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let new_pin = [0x2; 16];
        let result = app_session.change_pin(new_pin);
        assert!(result.is_ok(), "result {:?}", result);

        // Reset the pin back to the default
        let original_pin = TEST_CRED_PIN;
        let result = app_session.change_pin(original_pin);
        assert!(result.is_ok(), "result {:?}", result);
    });
}
#[test]
fn test_change_pin_multiple_times() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        let new_pin = [0x2; 16];
        let result = app_session.change_pin(new_pin);
        assert!(result.is_ok(), "result {:?}", result);

        let new_pin = [0x3; 16];
        let result = app_session.change_pin(new_pin);
        assert!(result.is_ok(), "result {:?}", result);

        // Reset the pin back to the default
        let original_pin = TEST_CRED_PIN;
        let result = app_session.change_pin(original_pin);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_change_pin_open_session_with_new_pin() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let new_pin = [0x3; 16];
        let result = app_session.change_pin(new_pin);
        assert!(result.is_ok(), "result {:?}", result);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let new_credentials = HsmAppCredentials {
            id: Uuid::from_bytes(TEST_CRED_ID),
            pin: new_pin,
        };

        let result = device.open_session(device.get_api_revision_range().max, new_credentials);
        assert!(result.is_ok(), "result {:?}", result);

        let app_session2 = result.unwrap();

        // Reset the pin back to the default
        let original_pin = TEST_CRED_PIN;
        let result = app_session2.change_pin(original_pin);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_change_pin_null_pin() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let app_session = common_open_app_session(device);

        // Null pin should fail
        let null_pin = [0x0; 16];
        let result = app_session.change_pin(null_pin);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_change_pin_after_session_closed() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app_session = common_open_app_session(device);

        let result = app_session.close_session();
        assert!(result.is_ok(), "result {:?}", result);

        let new_pin = [0x2; 16];
        let result = app_session.change_pin(new_pin);
        assert!(result.is_err(), "result {:?}", result);

        // Opening a new session should work with the original credentials
        let _ = common_open_app_session(device);
    });
}
