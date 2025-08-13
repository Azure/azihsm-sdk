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
pub struct HkdfDeriveInput<'a> {
    pub secret_key: HsmKeyHandle,
    pub params: HkdfDeriveParameters<'a>,
    pub target_key_tag: Option<u16>,
    pub target_key_type: KeyType,
    pub target_key_properties: KeyProperties,
    pub curve: EccCurve,
    pub use_valid_keyhandle: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: HkdfDeriveInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);
            let mut secret = input.secret_key.clone();
            if input.use_valid_keyhandle {
                let result = generate_valid_secret(&mut app_session, input.curve);
                if let Ok(handle) = result {
                    secret = handle;
                }
            }

            let _ = app_session.hkdf_derive(
                &secret,
                input.params,
                input.target_key_tag,
                input.target_key_type,
                input.target_key_properties,
            );

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
