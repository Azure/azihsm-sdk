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
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::common_api::*;

#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary)]

pub struct FuzzOpenAppSessionInput {
    pub api_rev: HsmApiRevision,
    pub vault_id: [u8; 16],
    pub app_id: [u8; 16],
    pub app_pin: [u8; 16],
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: FuzzOpenAppSessionInput| {
    // Assuming common setup and cleanup functions are defined in the `common` module
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            // Create a HsmAppCredentials object from the fuzzed input
            let app_credentials = HsmAppCredentials {
                id: Uuid::from_bytes(input.app_id),
                pin: input.app_pin,
            };

            // Attempt to open the app session using the fuzzed input
            let result = device.open_session(input.api_rev, app_credentials);

            if let Ok(mut app_session) = result {
                let _ = app_session.close_session();
            }
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
