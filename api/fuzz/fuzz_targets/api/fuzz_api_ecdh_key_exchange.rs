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
pub struct EcdhKeyExchangeInput {
    pub priv_key: HsmKeyHandle,
    pub peer_pub_key: Vec<u8>,
    pub target_key_tag: Option<u16>,
    pub target_key_type: KeyType,
    pub target_key_properties: KeyProperties,
    pub curve: EccCurve,
    pub use_valid_keyhandle: bool,
    pub use_valid_peerpub: bool,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: EcdhKeyExchangeInput| {
    api_fuzz_test(
        api_fuzz_common_setup,
        api_fuzz_common_cleanup,
        &|device: &HsmDevice, _path: &str| {
            let mut app_session = common_open_app_session(device);

            let mut keyhandle = input.priv_key.clone();
            let mut peer_pub_key = input.peer_pub_key.clone();
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

                if input.use_valid_peerpub {
                    let result = app_session.ecc_generate(
                        input.curve,
                        None,
                        KeyProperties {
                            key_usage: KeyUsage::Derive,
                            key_availability: KeyAvailability::Session,
                        },
                    );

                    if let Ok(handle) = result {
                        let keyhandle2 = handle;
                        let result = app_session.export_public_key(&keyhandle2);

                        if let Ok(pub_key) = result {
                            peer_pub_key = pub_key;
                        }
                    }
                }
            }

            let _ = app_session.ecdh_key_exchange(
                &keyhandle,
                &peer_pub_key,
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
