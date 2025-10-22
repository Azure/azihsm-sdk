// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;
use uuid::Uuid;

use crate::common::*;

#[test]
fn test_open_session() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let _app_session = common_open_app_session(device);
    });
}

#[test]
fn test_open_session_multiple_single_handle() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let _app_session = common_open_app_session(device);

        let result = device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_err(), "result {:?}", result);
        assert_eq!(
            result.unwrap_err(),
            HsmError::OnlyOneSessionAllowedPerDeviceHandle
        );
    });
}

#[test]
fn test_open_session_multiple() {
    api_test(common_setup, common_cleanup, |device, path| {
        let _app_session = common_open_app_session(device);

        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);
        let device2 = result.unwrap();
        let result =
            device2.open_session(device2.get_api_revision_range().max, TEST_APP_CREDENTIALS_2);

        assert!(result.is_err(), "result {:?}", result);
    });
}
#[test]
fn test_open_session_incorrect_revision() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut api_rev = device.get_api_revision_range().max;
        api_rev.major += 1;

        let result = device.open_session(api_rev, TEST_APP_CREDENTIALS);

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_open_session_without_manager_session() {
    api_test(common_setup, common_cleanup, |_device, path| {
        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);
        let device2 = result.unwrap();

        let result =
            device2.open_session(device2.get_api_revision_range().max, TEST_APP_CREDENTIALS_2);

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_open_session_without_create_app() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let result =
            device.open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS_2);

        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_open_session_unmatched_credential_pin() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app = TEST_APP_CREDENTIALS;
        app.pin[0] += 1;
        let result = device.open_session(device.get_api_revision_range().max, app);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_open_session_unmatched_credential_uuid() {
    api_test(common_setup, common_cleanup, |device, _path| {
        let mut app = TEST_APP_CREDENTIALS;
        app.id = Uuid::new_v4();
        let result = device.open_session(device.get_api_revision_range().max, app);
        assert!(result.is_err(), "result {:?}", result);
    });
}

#[test]
fn test_open_session_max_limit() {
    api_test(common_setup, common_cleanup, |device, path| {
        let max_sessions = MAX_SESSIONS;

        let mut device_handles: Vec<HsmDevice> = Vec::with_capacity(max_sessions + 1);

        //clean up the apps

        //cerate multiple handles
        for _ in 0..=max_sessions {
            let result = HsmDevice::open(path);
            assert!(result.is_ok(), "result {:?}", result);
            let device = result.unwrap();
            device_handles.push(device);
        }

        let app_session = common_open_app_session(device);
        let mut app_sessions: Vec<HsmSession> = Vec::with_capacity(max_sessions);
        app_sessions.push(app_session);

        for device_handle in device_handles.iter().take(max_sessions).skip(1) {
            let result = device_handle
                .open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
            assert!(result.is_ok(), "result {:?}", result);
            let app = result.unwrap();
            app_sessions.push(app);
        }

        //open session that is more than max_session should get VaultSessionLimitReached
        let result = device_handles[max_sessions]
            .open_session(device.get_api_revision_range().max, TEST_APP_CREDENTIALS);
        assert!(result.is_err(), "result {:?}", result);

        for mut app_session in app_sessions {
            let result = app_session.close_session();
            assert!(result.is_ok(), "result {:?}", result);
        }
        //clean  up
    })
}
