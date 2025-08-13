// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target creates a new key, then uses it to decrypt data.
// Windows imports
use windows::Win32::Security::Cryptography::*;

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
    azihsmksp_decrypt,
    DECRYPT_PLAINTEXT_BUFFER_MAXLEN,
    DECRYPT_CIPHERTEXT_BUFFER_MAXLEN,
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

    /// Information to pass to `NCryptEncrypt()`.
    pub decrypt: payloads::NCryptEncryptDecryptPayload,
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus
{
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // before we create the key, specify the usage of a valid algorithm. This
    // will prevent us from attempting to create a key with an invalid algorithm
    // name (i.e. a bunch of random bytes in a string). The point of this test
    // is to test decryption, and as such, we want to create a valid key to
    // decrypt with.
    //
    // (because the `FuzzInput` object is provided as read-only in the
    // `fuzz_target!()` macro, we must make a deep copy and make it mutable)
    let mut input = input.clone();
    input.decrypt.key.create.use_valid_algorithm = true;

    // request the creation of a key. If it fails, and we're running in
    // "careful" mode, return early
    let (result, key) = input.decrypt.key.create(azihsmksp);
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // finalize the key, then check for errors if we're in "careful" mode
    let result = input.decrypt.key.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // create an input buffer to store the ciphertext we want to decrypt (if
    // `input_buffer_is_enabled` is true)
    let mut inbuff;
    let mut inbuff_param: Option<&[u8]> = None;
    if input.decrypt.input_buffer_is_enabled
    {
        inbuff = input.decrypt.input_buffer.create(DECRYPT_CIPHERTEXT_BUFFER_MAXLEN);
        inbuff_param = Some(inbuff.as_mut_slice());
    }

    // create an output buffer to store the resulting plaintext, in the same
    // way as the plaintext buffer
    let mut outbuff;
    let mut outbuff_param: Option<&mut [u8]> = None;
    if input.decrypt.output_buffer_is_enabled
    {
        outbuff = input.decrypt.output_buffer.create(DECRYPT_PLAINTEXT_BUFFER_MAXLEN);
        outbuff_param = Some(outbuff.as_mut_slice());
    }

    // invoke the decryption function. Check the result, if we're in "careful"
    // mode
    let (result, _value) = azihsmksp_decrypt(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
        &input.decrypt,
        inbuff_param,
        outbuff_param
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // request the deletion of the key. Regardless of success or failure, this
    // test's work is done, so we'll exit and tell LibFuzzer to keep this input
    let _ = input.decrypt.key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});

