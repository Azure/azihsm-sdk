// Copyright (C) Microsoft Corporation. All rights reserved.

use mcr_ddi::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        type DdiTest = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        type DdiTest = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        type DdiTest = mcr_ddi_win::DdiWin;
    }
}

fn main() {
    let ddi = DdiTest::default();
    let dev_infos = ddi.dev_info_list();

    // Example expected output for single device:

    // ====Start Logging AziHSM device information
    // Device PCI info: "MCR:11858944:0:0"
    // AziHSM VF driver version: "2.0.472.0"
    // AziHSM FW ver: "5.1-50702174"
    // AziHSM HW ver: "1009567EFAB8FB3EAA72C3A288E0110D"
    // ====Done Logging AziHSM device information

    for dev_info in dev_infos.iter() {
        println!("====Start Logging AziHSM device information");

        let pci_info: &str = dev_info.pci_info.trim_end_matches(['\0', ' ']);
        println!("Device PCI info: {:?}", pci_info);

        let driver_ver: &str = dev_info.driver_ver.trim_end_matches(['\0', ' ']);
        println!("AziHSM VF driver version: {:?}", driver_ver);

        let firmware_ver: &str = dev_info.firmware_ver.trim_end_matches(['\0', ' ']);
        println!("AziHSM FW ver: {:?}", firmware_ver);

        let hardware_ver: &str = dev_info.hardware_ver.trim_end_matches(['\0', ' ']);
        println!("AziHSM HW ver: {:?}", hardware_ver);

        println!("====Done Logging AziHSM device information");
    }
}
