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
pub struct AesXtsEncryptDecryptInput {
    pub mode: AesMode,
    pub key_1: HsmKeyHandle,
    pub key_2: HsmKeyHandle,
    pub dul: usize,
    pub tweak: [u8; 16],
    pub data: Vec<u8>,
    pub digest_kind: DigestKind,
    pub use_valid_keyhandle1: bool,
    pub use_valid_keyhandle2: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: AesXtsEncryptDecryptInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle1 = input.key_1.clone();
            if input.use_valid_keyhandle1 {
                let result = rsa_unwrap_from_wrap_data(
                    &app_session,
                    KeyType::AesXtsBulk256,
                    input.digest_kind,
                    KeyUsage::EncryptDecrypt,
                );

                if let Ok(handle) = result {
                    keyhandle1 = handle;
                }
            }

            let mut keyhandle2 = input.key_2.clone();
            if input.use_valid_keyhandle2 {
                let result = rsa_unwrap_from_wrap_data(
                    &app_session,
                    KeyType::AesXtsBulk256,
                    input.digest_kind,
                    KeyUsage::EncryptDecrypt,
                );

                if let Ok(handle) = result {
                    keyhandle2 = handle;
                }
            }
            let _encrypt_result = app_session.aes_xts_encrypt_decrypt(
                input.mode,
                &keyhandle1,
                &keyhandle2,
                input.dul,
                input.tweak,
                input.data.clone(),
            );

            let _ = app_session.delete_key(&keyhandle1);

            let _ = app_session.delete_key(&keyhandle2);

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
