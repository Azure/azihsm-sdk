// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_api::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_open_valid_path() {
    api_test(common_setup, common_cleanup, |_device, path| {
        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);
        let _device = result.unwrap();
    });
    // validate _deive is dropped when out of scope?
}

#[test]
fn test_open_invalid_path() {
    let path = String::from("invalid_path");
    let result = HsmDevice::open(&path);
    assert!(result.is_err(), "result {:?}", result);
}

#[test]
fn test_open_multiple_times_device_dropped_before_next_open() {
    api_test(common_setup, common_cleanup, |_device, path| {
        {
            let result = HsmDevice::open(path);
            assert!(result.is_ok(), "result {:?}", result);
            let _device = result.unwrap();
        }

        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_multiple_times() {
    api_test(common_setup, common_cleanup, |_device, path| {
        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);

        let result = HsmDevice::open(path);
        assert!(result.is_ok(), "result {:?}", result);
    });
}

#[test]
fn test_open_multiple_handle_device_dropped_before_next_open() {
    let devices = HsmDevice::get_devices();

    let size = devices.len();
    assert!(size > 0);

    for device in devices {
        let result = HsmDevice::open(device.path.as_str());
        assert!(result.is_ok(), "result {:?}", result);
    }
}

#[test]
fn test_open_multiple_handle_device() {
    let devices = HsmDevice::get_devices();

    let size = devices.len();
    assert!(size > 0);

    let mut hmidevices: Vec<HsmDevice> = vec![];
    for device in devices {
        let result = HsmDevice::open(device.path.as_str());
        assert!(result.is_ok(), "result {:?}", result);
        hmidevices.push(result.unwrap());
    }
    hmidevices.clear();
}
