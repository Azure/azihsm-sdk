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
pub struct HmacInput<'a> {
    pub hmac_key: HsmKeyHandle,
    pub hmac_key_type: HmacInputKeyType,
    pub curve: EccCurve,
    pub hkdf_params: HkdfDeriveParameters<'a>,
    pub msg: Vec<u8>,
    pub use_valid_keyhandle: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: HmacInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);
            let mut hmac_key = input.hmac_key.clone();

            if input.use_valid_keyhandle {
                let result = generate_valid_hmacsha_key(
                    &mut app_session,
                    input.curve,
                    input.hkdf_params,
                    input.hmac_key_type,
                );
                if let Ok(handle) = result {
                    hmac_key = handle;
                }
            }

            let _ = app_session.hmac(hmac_key, input.msg.clone());

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
