// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target does the following:
///
/// 1. Creates a new key.
/// 2. Opens a new handle to the key.
/// 3. Closes the new handle of the key.
/// 4. Deletes the key.

// Windows imports
use windows::{
    Win32::Security::Cryptography::*,
};

// Fuzzing imports
use libfuzzer_sys::{
    fuzz_target,
    Corpus
};
use arbitrary::Arbitrary;

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_open,
    azihsmksp_close,
    azihsmksp_create_key,
    azihsmksp_open_key,
    azihsmksp_close_key,
    azihsmksp_delete_key,
    azihsmksp_finalize_key,
};
#[path = "lib/payloads.rs"]
mod payloads;

#[cfg(feature = "direct-invoke-dll")]
use crate::common::dll_init;

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes. This takes advantage of cargo-fuzz/libfuzzer's `Arbitrary`
/// object support, which allows the fuzzing target to receive any arbitrary
/// type.
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput
{
    /// Whether or not this test should run "carefully" (i.e., check return
    /// values from functions that may fail).
    pub careful: bool,

    /// Information to pass to `NCryptOpenKey()`.
    pub create_key: payloads::NCryptCreatePersistedKeyPayload,

    /// Information to pass to `NCryptOpenKey()`.
    pub open_key: payloads::NCryptOpenKeyPayload,

    /// Information to pass to `NCryptDeleteKey()`.
    pub delete_key: payloads::NCryptDeleteKeyPayload,

    /// Controls whether or not the `NCryptFinalizeKey()` function is performed
    /// after creating the key.
    pub do_finalize: bool,

    /// Information to pass to `NCryptFinalizeKey()`.
    pub finalize_key: payloads::NCryptFinalizeKeyPayload,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus
{
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut input = input.clone();
    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // request the creation of a key. If it fails, and we're running in
    // "careful" mode, return early
    let mut key = NCRYPT_KEY_HANDLE(0);
    let result = azihsmksp_create_key(azihsmksp, &mut key, &input.create_key);
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finalize the key, if `do_finalize` is enabled
    if input.do_finalize
    {
        // finalize, then check for errors if we're in "careful" mode
        let result = azihsmksp_finalize_key(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input.finalize_key
        );
        if input.careful && result.is_err()
        {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    }

    // next, open a new handle to the key we just created. (modify the
    // `open_key` payload to use the same key name as the `create_key` payload)
    input.open_key.key_name = input.create_key.key_name.clone();
    let mut key2 = NCRYPT_KEY_HANDLE(0);
    let result = azihsmksp_open_key(azihsmksp, &mut key2, &input.open_key);
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // close the key handle
    let result = azihsmksp_close_key(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key2,
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finally, delete the key. Regardless of success or failure, this test's
    // work is done, so we'll exit and tell LibFuzzer to keep this input
    let _ = azihsmksp_delete_key(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.delete_key
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});

