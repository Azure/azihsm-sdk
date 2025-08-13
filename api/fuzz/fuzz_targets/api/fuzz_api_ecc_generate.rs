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
#[derive(Debug, Arbitrary)]
pub struct EccGenerateInput {
    pub curve: EccCurve,
    pub key_tag: Option<u16>,
    pub key_properties: KeyProperties,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: EccGenerateInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let _ = app_session.ecc_generate(input.curve, input.key_tag, input.key_properties);

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
