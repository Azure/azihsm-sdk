// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target creates a new key through the AZIHSMKSP.
// Windows imports
use windows::Win32::Security::Cryptography::*;

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_close, azihsmksp_create_key, azihsmksp_delete_key, azihsmksp_finalize_key,
    azihsmksp_open,
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
    pub careful: bool,

    /// Information to pass to `NCryptCreatePersistedKey()`.
    pub create_key: payloads::NCryptCreatePersistedKeyPayload,

    /// Information to pass to `NCryptDeleteKey()`.
    pub delete_key: payloads::NCryptDeleteKeyPayload,

    /// Controls whether or not the `NCryptFinalizeKey()` function is performed
    /// after creating the key.
    pub do_finalize: bool,

    /// Information to pass to `NCryptFinalizeKey()`.
    pub finalize_key: payloads::NCryptFinalizeKeyPayload,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // request the creation of a key. If it fails, and we're running in
    // "careful" mode, return early
    let mut key = NCRYPT_KEY_HANDLE(0);
    let result = azihsmksp_create_key(azihsmksp, &mut key, &input.create_key);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finalize the key, if `do_finalize` is enabled
    if input.do_finalize {
        // finalize, then check for errors if we're in "careful" mode
        let result = azihsmksp_finalize_key(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input.finalize_key
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    }

    // request the deletion of the key. Regardless of success or failure, this
    // test's work is done, so we'll exit and tell LibFuzzer to keep this input
    let _ = azihsmksp_delete_key(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.delete_key
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
