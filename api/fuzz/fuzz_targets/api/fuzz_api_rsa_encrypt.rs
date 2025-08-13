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
pub struct RsaEncryptInput {
    pub keyhandle: HsmKeyHandle,
    pub data: Vec<u8>,
    pub padding: RsaCryptoPadding,
    pub hash_algorithm: Option<DigestKind>,
    pub key_type: RSAInputKeyType,
    pub digest_kind: DigestKind,
    pub use_valid_keyhandle: bool,
    pub label: Option<Vec<u8>>,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: RsaEncryptInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle = input.keyhandle.clone();
            if input.use_valid_keyhandle {
                let key_type = rsa_input_key_type_to_key_type(input.key_type);

                let result = rsa_unwrap_from_wrap_data(
                    &app_session,
                    key_type,
                    input.digest_kind,
                    KeyUsage::EncryptDecrypt,
                );

                if let Ok(handle) = result {
                    keyhandle = handle;
                }
            }

            let _ = app_session.rsa_encrypt(
                &keyhandle,
                input.data.clone(),
                input.padding,
                input.hash_algorithm,
                input.label.as_deref(),
            );

            let _ = app_session.delete_key(&keyhandle);

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
