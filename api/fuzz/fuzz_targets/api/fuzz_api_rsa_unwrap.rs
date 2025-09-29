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
pub struct RsaUnwrapInput {
    pub keyhandle: HsmKeyHandle,
    pub wrapped_blob: Vec<u8>,
    pub wrapped_blob_params: RsaUnwrapParams,
    pub target_key_tag: Option<u16>,
    pub target_key_properties: KeyProperties,
    pub usage: KeyUsage,
    pub key_type: RSAInputKeyType,
    pub digest_kind: DigestKind,
    pub use_valid_keyhandle: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: RsaUnwrapInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle = input.keyhandle.clone();
            if input.use_valid_keyhandle {
                // Get handle to private wrapping key
                let result = app_session.get_unwrapping_key();

                if let Ok(handle) = result {
                    keyhandle = handle;
                }
            }

            let _ = app_session.rsa_unwrap(
                &keyhandle,
                input.wrapped_blob.clone(),
                input.wrapped_blob_params,
                input.target_key_tag,
                input.target_key_properties,
            );

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
