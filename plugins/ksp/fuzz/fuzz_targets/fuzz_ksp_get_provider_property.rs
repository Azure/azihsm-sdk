// Copyright (C) Microsoft Corporation. All rights reserved.
#![cfg_attr(target_os = "windows", no_main)]

use arbitrary::Arbitrary;
/// This fuzzing target invokes `NCryptGetProperty()` on the AZIHSM KSP
/// handle to retrieve properties from the provider.
// Fuzzing imports
use libfuzzer_sys::{fuzz_target, Corpus};

// Windows imports
use windows::Win32::Security::Cryptography::*;

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_close, azihsmksp_get_provider_property, azihsmksp_open, PROPERTY_BUFFER_MAXLEN,
};
#[path = "lib/payloads.rs"]
mod payloads;

#[cfg(feature = "direct-invoke-dll")]
use crate::common::dll_init;

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes. This takes advantage of cargo-fuzz/libfuzzer's `Arbitrary`
/// object support, which allows the fuzzing target to receive any arbitrary
/// type.
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Whether or not this test should run "carefully" (i.e., check return
    /// values from functions that may fail).
    #[allow(dead_code)]
    pub careful: bool,

    /// Information to pass to `NCryptGetProperty()`.
    pub get_property: payloads::NCryptGetPropertyPayload,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // we'll either pass *no* buffer into `NCryptGetProperty`, or we'll pass in
    // a buffer of a random length, filled with random data. The
    // `buffer_is_enabled` field will decide which route we'll go with
    let mut buffer;
    let mut buffer_param: Option<&mut [u8]> = None;
    if input.get_property.buffer_is_enabled {
        buffer = input.get_property.buffer.create(PROPERTY_BUFFER_MAXLEN);
        buffer_param = Some(buffer.as_mut_slice());
    }

    // retreive the property. Because this is the only operation we're doing in
    // this test, we don't need to worry about "careful" mode (where we would
    // check the return value for errors).  Though, the `careful` field is left
    // in this test in case it is modified in the future.
    let (_result, _value) =
        azihsmksp_get_provider_property(azihsmksp, &input.get_property, buffer_param);

    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
