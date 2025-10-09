// Copyright (C) Microsoft Corporation. All rights reserved.

#![allow(dead_code)]

use mcr_api_resilient::*;
use mcr_ddi::Ddi;
use mcr_ddi::DdiDev;
use mcr_ddi_types::*;
use uuid::Uuid;

cfg_if::cfg_if! {
    if #[cfg(feature = "mock")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_mock::DdiMock;
    } else if #[cfg(target_os = "linux")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_nix::DdiNix;
    }
    else if #[cfg(target_os = "windows")] {
        #[allow(dead_code)]
        pub type DdiTest = mcr_ddi_win::DdiWin;
    }
}

// 70FCF730-B876-4238-B835-8010CE8A3F76
pub(crate) const TEST_CRED_ID: [u8; 16] = [
    0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A, 0x3F, 0x76,
];

// DB3DC77F-C22E-4300-80D4-1B31B6F04800
pub(crate) const TEST_CRED_PIN: [u8; 16] = [
    0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0, 0x48, 0x00,
];

pub const TEST_CREDENTIALS: HsmAppCredentials = HsmAppCredentials {
    id: Uuid::from_bytes(TEST_CRED_ID),
    pin: TEST_CRED_PIN,
};

/// Helper function to set device kind by querying device info
#[allow(dead_code)]
fn set_device_kind(device: &mut <DdiTest as Ddi>::Dev) -> Result<(), Box<dyn std::error::Error>> {
    let req = DdiGetDeviceInfoCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::GetDeviceInfo,
            sess_id: None,
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiGetDeviceInfoReq {},
        ext: None,
    };
    let mut cookie = None;
    let resp_info = device.exec_op(&req, &mut cookie)?;
    device.set_device_kind(resp_info.data.kind);
    Ok(())
}

pub fn get_device_path_helper() -> String {
    let devices = HsmDevice::get_devices();

    // Return the device info for the first device
    let dev_info = &devices[0];
    dev_info.path.clone()
}

#[allow(dead_code)]
pub fn simulate_live_migration_helper(path: &str) {
    let ddi = DdiTest::default();

    let mut lm_dev = ddi.open_dev(path).unwrap();
    set_device_kind(&mut lm_dev).unwrap();

    lm_dev.simulate_nssr_after_lm().unwrap();
}

pub fn common_cleanup(path: &str) {
    // Use mcr_api so we have access to clear_device
    let result = mcr_api::HsmDevice::open(path);
    assert!(result.is_ok(), "result {:?}", result);
    let device = result.unwrap();

    // Establish credential can only happen once so it could fail
    // in future instances so ignore error
    let api_rev = device.get_api_revision_range().max;
    let masked_bk3 = device.init_bk3(api_rev, &[1u8; 48]).unwrap();
    let resp = device.establish_credential(api_rev, TEST_CREDENTIALS, masked_bk3, None, None);
    if let Err(resp) = resp {
        println!("establish credential failed with {}. Ignoring since establish credential can only be done once and may have happened before", resp);
    } else {
        println!("establish credential succeeded");
    }

    let result = device.open_session(device.get_api_revision_range().max, TEST_CREDENTIALS);
    assert!(result.is_ok(), "result {:?}", result);
    let mut session = result.unwrap();

    let result = session.clear_device();
    assert!(result.is_ok(), "clear_device result {:?}", result);
}

/// Helper function to set up a device with established credentials
pub fn setup_device_with_credentials(device_path: &str) -> (HsmDevice, HsmApiRevision) {
    let device = HsmDevice::open(device_path).expect("Failed to open HSM device");
    let api_rev = device.get_api_revision_range().max;

    device
        .establish_credential(api_rev, TEST_CREDENTIALS)
        .expect("Failed to establish credentials");
    (device, api_rev)
}

/// Helper function to set up a device and open a session
pub fn setup_device_and_session(device_path: &str) -> (HsmDevice, HsmSession, HsmApiRevision) {
    let (device, api_rev) = setup_device_with_credentials(device_path);
    let session = device
        .open_session(api_rev, TEST_CREDENTIALS)
        .expect("Failed to open session");
    (device, session, api_rev)
}

pub(crate) const SESSION_KEY_PROPERTIES: KeyProperties = KeyProperties {
    key_usage: KeyUsage::EncryptDecrypt,
    key_availability: KeyAvailability::Session,
};

/// Helper function to generate an AES session key
pub fn generate_session_aes_key(session: &HsmSession, error_context: &str) -> HsmKeyHandle {
    let result = session.aes_generate(AesKeySize::Aes256, None, SESSION_KEY_PROPERTIES);

    match result {
        Ok(key_handle) => key_handle,
        Err(e) => panic!("{}: {:?}", error_context, e),
    }
}
