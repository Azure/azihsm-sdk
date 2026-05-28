// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(test)]

use azihsm_ddi::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_ddi_dev_info() {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();

    assert_ne!(dev_infos.len(), 0);

    for dev_info in dev_infos.iter() {
        println!("====Start Logging Lion device information");

        println!("Device PCI info: {:?}", dev_info.pci_info);

        println!("Lion driver version: {:?}", dev_info.driver_ver);

        println!("Lion FW ver: {:?}", dev_info.firmware_ver);

        println!("Lion HW ver: {:?}", dev_info.hardware_ver);

        println!("====Done Logging Lion device information");
    }
}
