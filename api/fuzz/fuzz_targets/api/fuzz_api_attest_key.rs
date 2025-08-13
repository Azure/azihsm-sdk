// Copyright (C) Microsoft Corporation. All rights reserved.
#![cfg_attr(target_os = "linux", no_main)]

#[cfg(target_os = "linux")]
mod common_api;
#[cfg(target_os = "linux")]
use arbitrary::Arbitrary;
#[cfg(target_os = "linux")]
use libfuzzer_sys::fuzz_target;
#[cfg(target_os = "linux")]
use mcr_api::*;

#[cfg(target_os = "linux")]
use crate::common_api::*;

#[cfg(target_os = "linux")]
const REPORT_DATA_SIZE: usize = 128;

#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary)]
pub struct AttestKeyInput {
    pub key: HsmKeyHandle,
    pub report_data: [u8; REPORT_DATA_SIZE],
    pub curve: EccCurve,
    pub use_valid_keyhandle: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: AttestKeyInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle = input.key.clone();
            if input.use_valid_keyhandle {
                let result = app_session.ecc_generate(
                    input.curve,
                    None,
                    KeyProperties {
                        key_usage: KeyUsage::Derive,
                        key_availability: KeyAvailability::Session,
                    },
                );

                if let Ok(handle) = result {
                    keyhandle = handle;
                }
            }

            let _ = app_session.attest_key(&keyhandle, &input.report_data);

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
