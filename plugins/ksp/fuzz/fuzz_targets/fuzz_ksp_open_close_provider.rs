// Copyright (C) Microsoft Corporation. All rights reserved.
#![cfg_attr(target_os = "windows", no_main)]

use arbitrary::Arbitrary;
/// This fuzzing target is very simple: it simply opens a AZIHSM provider
/// (KSP) via the NCrypt API, then closes it.
// Fuzzing imports
use libfuzzer_sys::{
    fuzz_target,
    Corpus
};

// Windows imports.
//
// See the Rust docs for the Windows Cryptography API here:
// https://microsoft.github.io/windows-docs-rs/doc/windows/Win32/Security/Cryptography/
#[cfg(target_os = "windows")]
use windows::Win32::Security::Cryptography::NCRYPT_PROV_HANDLE;

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{azihsmksp_close, azihsmksp_open};
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
    /// An integer representing the flags to use to open each provider (the
    /// parameter to `NCryptOpenStorageProvider()`).
    pub provider_flags: payloads::NCryptFlags,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    let result = azihsmksp_open(&input.provider_flags, &mut azihsmksp);
    if result.is_err() {
        return Corpus::Keep;
    }

    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
