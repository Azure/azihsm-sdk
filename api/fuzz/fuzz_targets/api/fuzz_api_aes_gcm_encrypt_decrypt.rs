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
pub struct AesGcmEncryptDecryptInput {
    pub key: HsmKeyHandle,
    pub mode: AesMode,
    pub data: Vec<u8>,
    pub iv: [u8; 12],
    pub aad: Option<Vec<u8>>,
    pub tag: Option<[u8; 16]>,
    pub digest_kind: DigestKind,
    pub use_valid_keyhandle: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: AesGcmEncryptDecryptInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle = input.key.clone();
            if input.use_valid_keyhandle {
                let result = rsa_unwrap_from_wrap_data(
                    &app_session,
                    KeyType::AesBulk256,
                    input.digest_kind,
                    KeyUsage::EncryptDecrypt,
                );

                if let Ok(handle) = result {
                    keyhandle = handle;
                }
            }
            let _encrypt_result = app_session.aes_gcm_encrypt_decrypt(
                &keyhandle,
                input.mode,
                input.data.clone(),
                input.iv,
                input.aad.clone(),
                None, // No tag provided for encryption
            );

            let _ = app_session.delete_key(&keyhandle);

            let _ = app_session.close_session();
        },
    );
});

#[cfg(target_os = "windows")]
fn main() {}
