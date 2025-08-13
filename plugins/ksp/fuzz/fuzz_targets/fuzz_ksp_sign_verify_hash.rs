// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target does the following:
///
/// 1. Creates a new key.
/// 2. Uses the key to sign a randomly-generated hash.
/// 3. Uses the key to verify the generated signature (or, a randomly-generates
///    signature).
/// 4. Deletes the key.
// Windows imports
use windows::{core::*, Win32::Security::Cryptography::*};

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{
    azihsmksp_close, azihsmksp_open, azihsmksp_sign_hash, azihsmksp_verify_signature,
    HASH_BUFFER_MAXLEN, SIGNATURE_BUFFER_MAXLEN,
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

    /// Information to pass into key-related functions, in order to create and
    /// interact with a key used to sign and verify the hash in this fuzzing
    /// test.
    pub key: payloads::NCryptKeyPayload,

    /// Information to pass to `NCryptSignHash()`.
    pub sign_hash: payloads::NCryptSignHashPayload,

    /// Information to pass to `NCryptVerifySignature()`.
    pub verify_signature: payloads::NCryptVerifySignaturePayload,

    /// If this is true, the fuzzing target will use the same hash value for
    /// both `NCryptSignHash()` and `NCryptVerifySignature()`. If it's false,
    /// two different hash values will be used.
    ///
    /// This lets us test two scenarios:
    ///
    /// 1. Signing, then verifying the exact same hash value (the expected use
    ///    case).
    /// 2. Signing one hash, then attempting to verify a with completely
    ///    different hash.
    ///
    /// Both approaches may create different, interesting behavior in the KSP.
    pub use_identical_hash: bool,

    /// If this is true, the fuzzing target will pass the same signature value
    /// that was generated in `NCryptSignHash()` into `NCryptVerifySignature()`.
    /// If it's false, a completely differnt signature value will be passed into
    /// `NCryptVerifySignature()`.
    ///
    /// This lets us test two scenarios:
    ///
    /// 1. Signing a hash, then verifying the signature that was generated (the
    ///    expect use case).
    /// 2. Signing a hash, then attempting to verify a completely different
    ///    signature.
    ///
    /// Both approaches may create different, interesting behavior in the KSP.
    pub use_identical_signature: bool,
}

/// Helper function that invokes `NCryptSignHash()`.
fn fuzz_target_sign_hash(
    #[cfg(feature = "direct-invoke-dll")] azihsmksp: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptSignHashPayload,
) -> (Result<()>, u32) {
    // create a buffer (or don't) to pass in as the signature output buffer.
    // This parameter is optional, and `NCryptSignHash()` (and the underlying
    // KSP) will behave differently depending on if the buffer is passed in or
    // not. So, we do this to test both scenarios.
    let mut sign_buffer;
    let mut sign_buffer_param: Option<&mut [u8]> = None;
    if input.sign_buffer_is_enabled {
        sign_buffer = input.sign_buffer.create(SIGNATURE_BUFFER_MAXLEN);
        sign_buffer_param = Some(sign_buffer.as_mut_slice());
    }

    // create a hash buffer to pass into `NCryptSignHash()`
    let hash_buffer = input.hash_buffer.create(HASH_BUFFER_MAXLEN);

    let (result, value) =
        azihsmksp_sign_hash(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input,
            hash_buffer.as_slice(),
            sign_buffer_param
        );
    (result, value)
}

/// Helper function that invokes `NCryptVerifySignature()`.
fn fuzz_target_verify_signature(
    #[cfg(feature = "direct-invoke-dll")] azihsmksp: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
    input: &payloads::NCryptVerifySignaturePayload,
) -> Result<()> {
    // create two buffers for the hash and the signature
    let hash_buffer = input.hash_buffer.create(HASH_BUFFER_MAXLEN);
    let sign_buffer = input.sign_buffer.create(SIGNATURE_BUFFER_MAXLEN);

    let result =
        azihsmksp_verify_signature(
            #[cfg(feature = "direct-invoke-dll")] azihsmksp,
            key,
            &input,
            hash_buffer.as_slice(),
            sign_buffer.as_slice()
        );
    result
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut input = input.clone();
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

    // ------------------------ Signature Generation ------------------------ //
    let (result, _value) = fuzz_target_sign_hash(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.sign_hash
    );
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // ----------------------- Signature Verification ----------------------- //
    // if we're using the same hash value for both signing and verifying, modify
    // the `verify_signature` payload to copy the hash from the `sign_hash`
    // payload
    if input.use_identical_hash {
        input.verify_signature.hash_buffer = input.sign_hash.hash_buffer.clone();
    }

    // similarly, if we're using the same signature value, do the same:
    if input.use_identical_signature {
        input.verify_signature.sign_buffer = input.sign_hash.sign_buffer.clone();
    }

    let result = fuzz_target_verify_signature(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.verify_signature
    );
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
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
