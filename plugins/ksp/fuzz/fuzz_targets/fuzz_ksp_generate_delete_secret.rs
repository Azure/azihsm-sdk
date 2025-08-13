// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "windows", no_main)]

/// This fuzzing target does the following:
///
/// 1. Creates a private key.
/// 2. Creates a public key.
/// 3. Uses both keys to generate a secret with `NCryptSecretAgreement()`.
/// 4. Deletes the secret.
/// 5. Deletes the keys.
// Windows imports
use windows::{core::*, Win32::Security::Cryptography::*};

// Fuzzing imports
use arbitrary::Arbitrary;
use libfuzzer_sys::{fuzz_target, Corpus};

// Local imports
#[path = "lib/common.rs"]
mod common;
use crate::common::{azihsmksp_close, azihsmksp_open, azihsmksp_secret_agreement};
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

    /// Information to pass to `NCryptSecretAgreement()`.
    pub secret_agreement: payloads::NCryptSecretAgreementPayload,
}

/// Helper function for creating keys.
fn fuzz_target_make_key(
    azihsmksp: NCRYPT_PROV_HANDLE,
    input: &FuzzInput,
    key_input: &payloads::NCryptKeyPayload,
) -> (Result<()>, NCRYPT_KEY_HANDLE) {
    // create the key
    let (result, key) = key_input.create(azihsmksp);
    if input.careful && result.is_err() {
        return (result, NCRYPT_KEY_HANDLE(0));
    }

    // finalize the key
    let result = key_input.finalize(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        key,
    );
    if input.careful && result.is_err() {
        return (result, NCRYPT_KEY_HANDLE(0));
    }

    (Ok(()), key)
}

// Function invoked by LibFuzzer.
fuzz_target!(|input: FuzzInput| -> Corpus {
    #[cfg(feature = "direct-invoke-dll")] {
        dll_init().expect("Failed to initialize DLL");
    }

    let mut input = input.clone();
    let mut azihsmksp: NCRYPT_PROV_HANDLE = NCRYPT_PROV_HANDLE(0);
    azihsmksp_open(&0u32.into(), &mut azihsmksp).expect("Failed to load provider");

    // create the public and private keys; we need these to generate a secret
    // (make sure both payloads are set to use valid key algorithms. We want
    // these keys to be created successfully, so we can use them for generating
    // secrets)
    input
        .secret_agreement
        .private_key
        .create
        .use_valid_algorithm = true;
    input.secret_agreement.public_key.create.use_valid_algorithm = true;
    let (result, private_key) =
        fuzz_target_make_key(azihsmksp, &input, &input.secret_agreement.private_key);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }
    let (result, public_key) =
        fuzz_target_make_key(azihsmksp, &input, &input.secret_agreement.public_key);
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // use the two keys to generate a secret
    let (result, _secret) = azihsmksp_secret_agreement(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        private_key,
        public_key,
        &input.secret_agreement,
    );
    if input.careful && result.is_err() {
        azihsmksp_close(azihsmksp);
        return Corpus::Keep;
    }

    // delete/close the secret
    // TODO - not sure how to do this. What NCrypt function can we call to
    // execute `azihsm_delete_secret()`?

    // delete both public and private keys
    let _ = input.secret_agreement.private_key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        private_key,
    );
    let _ = input.secret_agreement.public_key.delete(
        #[cfg(feature = "direct-invoke-dll")] azihsmksp,
        public_key,
    );
    azihsmksp_close(azihsmksp);
    Corpus::Keep
});
