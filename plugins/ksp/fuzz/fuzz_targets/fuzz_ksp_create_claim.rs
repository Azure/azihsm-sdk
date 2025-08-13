// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target does the following:
///
/// 1. Creates a subject key.
/// 2. Creates an authority key.
/// 3. Uses both keys to generate a claim with `NCryptCreateClaim()`.
/// 4. Deletes the keys.

// Windows imports
use windows::{
    core::*,
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
    azihsmksp_create_claim,
    CLAIM_BUFFER_MAXLEN,
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

    /// Parameters to pass into `NCryptCreateClaim()`.
    pub create_claim: payloads::NCryptCreateClaimPayload,
}

/// Helper function for creating keys.
fn fuzz_target_make_key(
        azihsmksp: NCRYPT_PROV_HANDLE,
        input: &FuzzInput,
        key_input: &payloads::NCryptKeyPayload
    ) -> (Result<()>, NCRYPT_KEY_HANDLE)
{
    // create the key
    let (result, key) = key_input.create(azihsmksp);
    if input.careful && result.is_err()
    {
        return (result, NCRYPT_KEY_HANDLE(0))
    }

    // finalize the key
    let result = key_input.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err()
    {
        return (result, NCRYPT_KEY_HANDLE(0))
    }

    (Ok(()), key)
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

    // create the subject and authority keys; we need these to generate a claim
    // (make sure both payloads are set to use valid key algorithms. We want
    // these keys to be created successfully, so we can use them for generating
    // secrets)
    input.create_claim.subject_key.create.use_valid_algorithm = true;
    input.create_claim.authority_key.create.use_valid_algorithm = true;
    let (result, subject_key) = fuzz_target_make_key(
        azihsmksp,
        &input,
        &input.create_claim.subject_key
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }
    let (result, authority_key) = fuzz_target_make_key(
        azihsmksp,
        &input,
        &input.create_claim.authority_key
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // set up a buffer (or don't) to pass into `NCryptCreateClaim()`. Because
    // the parameter is optional, we want to fuzz both scenarios
    let mut blob_buffer;
    let mut blob_buffer_param: Option<&mut [u8]> = None;
    if input.create_claim.blob_buffer_is_enabled
    {
        blob_buffer = input.create_claim.blob_buffer.create(CLAIM_BUFFER_MAXLEN);
        blob_buffer_param = Some(blob_buffer.as_mut_slice());
    }

    // create the claim
    let (result, _value) = azihsmksp_create_claim(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        subject_key,
        authority_key,
        &input.create_claim,
        blob_buffer_param
    );
    if input.careful && result.is_err()
    {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // delete both public and private keys
    let _ = input.create_claim.subject_key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        subject_key,
    );
    let _ = input.create_claim.authority_key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        authority_key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});

