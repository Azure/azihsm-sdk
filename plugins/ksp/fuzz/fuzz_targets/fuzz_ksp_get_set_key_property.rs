// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target creates a new key, then sets and gets a property from
/// it. The key is deleted before the fuzzing target exits.
///
/// As you'll see in the `FuzzInput` struct, the "set" operation and the "get"
/// operation are given different priorities, which dictates the order in which
/// they occur. In this way, this fuzzing target can test both orders of
/// operations:
///
/// 1. `NCryptSetProperty()`, then `NCryptGetProperty()`
/// 2. `NCryptGetProperty()`, then `NCryptSetProperty()`

// Windows imports
#[cfg(target_os = "windows")]
use windows::{
    core::*,
    Win32::Security::Cryptography::{
        NCRYPT_KEY_HANDLE,
        NCRYPT_PROV_HANDLE,
    },
};

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_close, azihsmksp_get_key_property, azihsmksp_open, azihsmksp_set_key_property,
    PROPERTY_BUFFER_MAXLEN,
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

    /// Information to pass to key-related functions, to create and use a key
    /// with which we'll get/set properties.
    pub key: payloads::NCryptKeyPayload,

    /// Information to pass to `NCryptGetProperty()`.
    pub get_property: payloads::NCryptGetPropertyPayload,

    /// An integer representing the priority at which the call to
    /// `NCryptGetProperty()` should be called.
    ///
    /// (This determines the order in which `NCryptGetProperty()` and
    /// `NCryptSetProperty()` are called.)
    pub get_property_priority: u32,

    /// Information to pass to `NCryptSetProperty()`.
    pub set_property: payloads::NCryptSetPropertyPayload,

    /// An integer representing the priority at which the call to
    /// `NCryptSetProperty()` should be called.
    ///
    /// (This determines the order in which `NCryptGetProperty()` and
    /// `NCryptSetProperty()` are called.)
    pub set_property_priority: u32,
}

/// Helper function for the fuzzing target that invokes `NCryptGetProperty()`.
fn fuzz_target_get_property(
    #[cfg(feature = "direct-invoke-dll")] azihsmksp: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &FuzzInput
) -> Result<()> {
    // we'll either pass *no* buffer into `NCryptGetProperty`, or we'll pass in
    // a buffer of a random length, filled with random data. The
    // `buffer_is_enabled` field will decide which route we'll go with
    let mut buffer;
    let mut buffer_param: Option<&mut [u8]> = None;
    if input.get_property.buffer_is_enabled {
        buffer = input.get_property.buffer.create(PROPERTY_BUFFER_MAXLEN);
        buffer_param = Some(buffer.as_mut_slice());
    }

    let (result, _value) = azihsmksp_get_key_property(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.get_property,
        buffer_param
    );
    result
}

/// Helper function for the fuzzing target that invokes `NCryptSetProperty()`.
fn fuzz_target_set_property(
    #[cfg(feature = "direct-invoke-dll")] azihsmksp: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &FuzzInput
) -> Result<()> {
    // create a buffer to pass into `NCryptSetProperty`
    let mut buffer = input.set_property.buffer.create(PROPERTY_BUFFER_MAXLEN);

    azihsmksp_set_key_property(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.set_property,
        buffer.as_mut_slice(),
    )
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
    let (result, key) = input.key.create(azihsmksp);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finalize the key
    let result = input.key.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // compare the get/set priorities, and call the functions in the order
    // dictated by the higher priority value
    // ------------ SCENARIO 1: GET property, then SET property ------------- //
    if input.get_property_priority >= input.set_property_priority {
        // OPERATION 1: get property
        let result = fuzz_target_get_property(
           #[cfg(feature = "direct-invoke-dll")] azihsmksp,
           key,
           &input,
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }

        // OPERATION 2: set property
        let result = fuzz_target_set_property(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    }
    // ------------ SCENARIO 2: SET property, then GET property ------------- //
    else {
        // OPERATION 1: set property
        let result = fuzz_target_set_property(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }

        // OPERATION 2: get property
        let result = fuzz_target_get_property(
           #[cfg(feature = "direct-invoke-dll")] azihsmksp,
           key,
           &input,
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    }

    // request the deletion of the key. Regardless of success or failure, this
    // test is done, so we'll exit and tell LibFuzzer to keep this input
    let _ = input.key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
