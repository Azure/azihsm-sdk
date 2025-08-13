// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzing target opens existing keys through the azihsmksp. No specific key
/// is targeted; any arbitrary key that can be opened via `NCryptOpenKey()` can
/// be attempted through this fuzzing target.
// Windows imports
use windows::Win32::Security::Cryptography::*;

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{azihsmksp_close, azihsmksp_close_key, azihsmksp_open, azihsmksp_open_key};
#[path = "lib/payloads.rs"]
mod payloads;

#[cfg(feature = "direct-invoke-dll")]
use crate::common::dll_init;

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes. This takes advantage of cargo-fuzz/libfuzzer's `Arbitrary`
/// object support, which allows the fuzzing target to receive any arbitrary
/// type.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Whether or not this test should run "carefully" (i.e., check return
    /// values from functions that may fail).
    pub careful: bool,

    /// Information to pass to `NCryptOpenKey()`.
    pub open_key: payloads::NCryptOpenKeyPayload,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // request the opening of an arbitrary key. If we're in "careful" mode,
    // check the return value and exit early on failure
    let mut key = NCRYPT_KEY_HANDLE(0);
    let result = azihsmksp_open_key(azihsmksp, &mut key, &input.open_key);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // close the opened key handle
    let _ = azihsmksp_close_key(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
