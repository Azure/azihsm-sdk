// Copyright (C) Microsoft Corporation. All rights reserved.
#![cfg_attr(target_os = "linux", no_main)]

#[cfg(target_os = "linux")]
#[path = "../common.rs"]
mod common;

#[cfg(target_os = "linux")]
use arbitrary::Arbitrary;
#[cfg(target_os = "linux")]
use libfuzzer_sys::fuzz_target;
#[cfg(target_os = "linux")]
use libfuzzer_sys::Corpus;
#[cfg(target_os = "linux")]
use mcr_ddi_sim::aesgcmxts::SessionAesGcmRequest;
#[cfg(target_os = "linux")]
use mcr_ddi_sim::aesgcmxts::SessionAesXtsRequest;
#[cfg(target_os = "linux")]
use mcr_ddi_sim::crypto::aes::AesMode;
#[cfg(target_os = "linux")]
use mcr_ddi_sim::dispatcher::Dispatcher;

/// A small enum to differentiate between dispatching an AES-GCM request and an
/// AES-XTS request.
#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary, Clone)]
enum FuzzAesType {
    AesGcm,
    AesXts,
}

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes.
#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Tells the test which type of AES fast-path operation to dispatch (GCM or
    /// XTS).
    aes_type: FuzzAesType,

    /// Tells the test which AES mode to submit for the GCM/XTS request.
    /// (Encrypt or decrypt)
    aes_mode: AesMode,

    /// Randomized AES-GCM request data.
    gcm_request: SessionAesGcmRequest,

    /// Randomized AES-XTS request data.
    xts_request: SessionAesXtsRequest,

    /// A vector of `Vec<u8>`, to be used as the source buffers to pass into
    /// `Dispatcher::dispatch_fp_aes_gcm_encrypt_decrypt()` and
    /// `Dispatcher::dispatch_fp_aes_xts_encrypt_decrypt()`.
    source_buffers: Vec<Vec<u8>>,

    /// A vector of `Vec<u8>`, to be used as the output buffers to pass into
    /// `Dispatcher::dispatch_fp_aes_gcm_encrypt_decrypt()` and
    /// `Dispatcher::dispatch_fp_aes_xts_encrypt_decrypt()`.
    destination_buffers: Vec<Vec<u8>>,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: FuzzInput| -> Corpus {
    // create a mutable clone of the input object; some of the fields within
    // need to be modified
    let mut input = input.clone();

    // create a new dispatcher object; return early on error
    let new_dispatcher_result = Dispatcher::new(4);
    if new_dispatcher_result.is_err() {
        return Corpus::Keep;
    }
    let dispatcher = new_dispatcher_result.unwrap();

    // dispatch either an AES-GCM or AES-XTS request
    match input.aes_type {
        FuzzAesType::AesGcm => {
            let _result = dispatcher.dispatch_fp_aes_gcm_encrypt_decrypt(
                input.aes_mode,
                input.gcm_request,
                input.source_buffers,
                input.destination_buffers.as_mut_slice(),
            );
        }
        FuzzAesType::AesXts => {
            let _result = dispatcher.dispatch_fp_aes_xts_encrypt_decrypt(
                input.aes_mode,
                input.xts_request,
                input.source_buffers,
                input.destination_buffers.as_mut_slice(),
            );
        }
    };

    Corpus::Keep
});

#[cfg(target_os = "windows")]
fn main() {}
