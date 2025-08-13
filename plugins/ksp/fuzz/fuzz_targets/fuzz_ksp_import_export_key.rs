// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target creates a new key, then attempts to export and import
/// it.
// Windows imports
use windows::{core::*, Win32::Security::Cryptography::*};

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_close, azihsmksp_export_key, azihsmksp_import_key, azihsmksp_open,
    EXPORT_KEY_BUFFER_MAXLEN, IMPORT_KEY_BUFFER_MAXLEN,
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
struct FuzzInput {
    /// Whether or not this test should run "carefully" (i.e., check return
    /// values from functions that may fail).
    pub careful: bool,

    /// Information to pass into key-related functions, to create and use a key for
    /// importing/exporting.
    pub key: payloads::NCryptKeyPayload,

    /// Information to pass to `NCryptImportKey()`.
    pub import_key: payloads::NCryptImportKeyPayload,

    /// A priority value which is used to decide the order in which
    /// `NCryptImportKey()` and `NCryptExportKey()` is called.
    pub import_key_priority: u32,

    /// Information to pass to `NCryptExportKey()`.
    pub export_key: payloads::NCryptExportKeyPayload,

    /// A priority value which is used to decide the order in which
    /// `NCryptImportKey()` and `NCryptExportKey()` is called.
    pub export_key_priority: u32,

    /// A flag that, if true, forces the fuzzing target to use the same
    /// encryption key for exporting and importing. This is handy for testing
    /// exports/imports that are using the same encryption key (the expected
    /// behavior), rather than two separate keys (the default behavior of this
    /// fuzzing test).
    ///
    /// We want to test both situations; both approaches may invoke interesting
    /// behavior in the target.
    pub use_identical_import_export_keys: bool,

    /// A flag that, if true, forces the fuzzing target to use the same blob
    /// type string for exporting and importing. This is handy for testing both
    /// scenarios:
    ///
    /// 1. Using the same blob type for importing and exporting the same key
    ///    (the expected use-case).
    /// 2. Using different blob types for importing and exporting the same key
    ///    (not the expected use-case, but something that may invoke interesting
    ///    behavior in the KSP).
    pub use_identical_blob_type: bool,
}

/// Creates a new key and returns an opened handle to it.
fn fuzz_target_make_new_key(
    azihsmksp: NCRYPT_PROV_HANDLE,
    input: &FuzzInput,
    key_input: &payloads::NCryptKeyPayload,
) -> (Result<()>, NCRYPT_KEY_HANDLE) {
    // create the key (return early on error)
    let (result, key) = key_input.create(azihsmksp);
    if input.careful && result.is_err() {
        return (result, NCRYPT_KEY_HANDLE(0));
    }

    // finalize the key (return early on error)
    let result = key_input.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err() {
        return (result, NCRYPT_KEY_HANDLE(0));
    }

    (Ok(()), key)
}

/// Optionally, a handle to a separate key can be passed into `NCryptImportKey`
/// and, which is used to decrypt an imported key.
///
/// This function examines the fields in the `FuzzInput` object and creates a
/// new key (or, it doesn't). In either case, a key handle is returned (either
/// NULL, or non-NULL).
fn fuzz_target_get_import_decryption_key(
    azihsmksp: NCRYPT_PROV_HANDLE,
    input: &FuzzInput,
) -> (Result<()>, NCRYPT_KEY_HANDLE) {
    if !input.import_key.use_decryption_key {
        return (Ok(()), NCRYPT_KEY_HANDLE(0));
    }
    fuzz_target_make_new_key(azihsmksp, input, &input.import_key.decryption_key)
}

/// Optionally, a handle to a separate key can be passed into `NCryptExportKey`
/// and, which is used to encrypt an exported key.
///
/// This function examines the fields in the `FuzzInput` object and creates a
/// new key (or, it doesn't). In either case, a key handle is returned (either
/// NULL, or non-NULL).
fn fuzz_target_get_export_encryption_key(
    azihsmksp: NCRYPT_PROV_HANDLE,
    input: &FuzzInput,
) -> (Result<()>, NCRYPT_KEY_HANDLE) {
    if !input.export_key.use_encryption_key {
        return (Ok(()), NCRYPT_KEY_HANDLE(0));
    }
    fuzz_target_make_new_key(azihsmksp, input, &input.export_key.encryption_key)
}

/// Exports the provided key.
fn fuzz_target_export_key(
    #[cfg(feature = "direct-invoke-dll")] azihsmksp: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    encryption_key: NCRYPT_KEY_HANDLE,
    input: &FuzzInput,
) -> (Result<()>, u32) {
    // create a buffer (or not) to pass into the export function
    let mut blob_buffer;
    let mut blob_buffer_param: Option<&mut [u8]> = None;
    if input.export_key.blob_data_is_enabled {
        blob_buffer = input.export_key.blob_data.create(EXPORT_KEY_BUFFER_MAXLEN);
        blob_buffer_param = Some(blob_buffer.as_mut_slice());
    }

    // export the key
    let (result, value) =
        azihsmksp_export_key(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            encryption_key,
            &input.export_key,
            blob_buffer_param
        );
    (result, value)
}

/// Imports a key.
fn fuzz_target_import_key(
    azihsmksp: NCRYPT_PROV_HANDLE,
    decryption_key: NCRYPT_KEY_HANDLE,
    input: &FuzzInput,
) -> (Result<()>, NCRYPT_KEY_HANDLE) {
    // create a buffer to pass into the import function
    let mut blob_buffer = input.import_key.blob_data.create(IMPORT_KEY_BUFFER_MAXLEN);

    // import the key
    let (result, imported_key) = azihsmksp_import_key(
        azihsmksp,
        decryption_key,
        &input.import_key,
        blob_buffer.as_mut_slice(),
    );
    (result, imported_key)
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    // create a mutable copy of the input struct, so we can modify the fields
    let mut input = input.clone();

    // open the KSP
    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // request the creation of a key. If it fails, and we're running in
    // "careful" mode, return early
    let (result, key) = input.key.create(azihsmksp);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finalize, then check for errors if we're in "careful" mode
    let result = input.key.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // --------- Key Export/Import Encryption/Decryption Key Setup ---------- //
    // create encryption keys for importing and exporting the key. These
    // functions will either return NULL key handles (in which case no keys will
    // be used to encrypt/decrypt the imported/exported key), or they will
    // return handles to newly-created keys.
    let (result, encryption_key) = fuzz_target_get_export_encryption_key(azihsmksp, &input);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // either create a completely separate decryption key, or use the exact same
    // key handle for decryption as we do for encryption
    let decryption_key;
    if input.use_identical_import_export_keys {
        decryption_key = encryption_key.clone();
    } else {
        let (result, dec_key) = fuzz_target_get_import_decryption_key(azihsmksp, &input);
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
        decryption_key = dec_key;
    }

    // ------------------------- Key Export/Import -------------------------- //
    // if the flag is enabled, make the import and export operations below use
    // the same blob type
    if input.use_identical_blob_type {
        input.import_key.blob_type = input.export_key.blob_type.clone();
    }

    // next, we'll import and export the key. Though, we'll change the order up,
    // which might cause some interesting behavior. Examine the two priority
    // fields and decide which order to call `NCryptImportKey()` and
    // `NCryptExportKey()` based on which one is larger.
    if input.export_key_priority >= input.import_key_priority {
        // ---------------- APPROACH 1: Export, then Import ----------------- //
        let (result, _value) = fuzz_target_export_key(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            encryption_key,
            &input
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }

        let (result, _key) = fuzz_target_import_key(azihsmksp, decryption_key, &input);
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    } else {
        // ---------------- APPROACH 2: Import, then Export ----------------- //
        let (result, _key) = fuzz_target_import_key(azihsmksp, decryption_key, &input);
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }

        let (result, _value) = fuzz_target_export_key(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            encryption_key,
            &input
        );
        if input.careful && result.is_err() {
            azihsmksp_close(azihsmksp);
            return Corpus::Keep;
        }
    }

    // delete the two encryption/decryption keys used during export/import
    if encryption_key.0 != 0 {
        let _ = input.export_key.encryption_key.delete(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            encryption_key,
        );
    }
    if decryption_key.0 != 0 {
        let _ = input.import_key.decryption_key.delete(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            decryption_key,
        );
    }

    // finally, delete the key. Regardless of success or failure, this test's
    // work is done, so we'll exit and tell LibFuzzer to keep this input
    let _ = input.key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
