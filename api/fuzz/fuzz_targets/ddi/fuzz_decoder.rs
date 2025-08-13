// Copyright (C) Microsoft Corporation. All rights reserved.
// Checking decoder for potential crashes by feeding random input data]
#![cfg_attr(target_os = "linux", no_main)]

// Imports
#[cfg(target_os = "linux")]
use arbitrary::Arbitrary;
#[cfg(target_os = "linux")]
use libfuzzer_sys::fuzz_target;
#[cfg(target_os = "linux")]
use libfuzzer_sys::Corpus;
#[cfg(target_os = "linux")]
use mcr_ddi_types::DdiDecoder;
#[cfg(target_os = "linux")]
use mcr_ddi_types::DdiReqHdr;

#[cfg(target_os = "linux")]
#[path = "../common.rs"]
mod common;
#[cfg(target_os = "linux")]
use crate::common::get_rand_ddi_request;

/// A struct containing several fields to adjust the manner in which this fuzz
/// target executes.
#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary, Clone)]
struct FuzzInput {
    /// Random bytes that are passed into `decode_hdr()` if `use_rand_data` is
    /// set to `true`.
    rand_data: Vec<u8>,

    /// If set to `true`, the fuzzing target will feed `rand_data` directly into
    /// `decode_hdr()`. If set to `false`, the below fields will be used to
    /// construct a valid, random header and DDI request object that is fed into
    /// `decode_hdr()`.
    use_rand_data: bool,

    /// A seed with which a random DDI request object will be generated.
    ///
    /// If `use_rand_data` is set to `false`, this will instead be used to
    /// generate a valid, but random, DDI request object to pass into
    /// `decode_hdr()`. By using an actual DDI requets object instead of a fully
    /// random buffer (`rand_data`), we make it easier for the fuzzer to explore
    /// the "valid header" execution space, which could allow the fuzzer to
    /// discover more behavior deeper within the API/DDI code.
    ///
    /// This also allows us to fuzz MBOR encoding, since we'll be encoding a
    /// randomly-generated header & request object before passing it to
    /// `decode_hdr()`.
    request_seed: u64,

    /// A DDI request header, to be used along with `request_seed`.
    request_header: DdiReqHdr,
}

// Testing decoder resiliency with random data as input
#[cfg(target_os = "linux")]
fuzz_target!(|input: FuzzInput| -> Corpus {
    // if we're using random data for this run, all we need to do is create a
    // new decoder and feed the input object's `rand_data` directly into it
    if input.use_rand_data {
        let mut decoder = DdiDecoder::new(input.rand_data.as_slice(), true);
        let _result_hdr = decoder.decode_hdr::<DdiReqHdr>();
        return Corpus::Keep;
    }

    // otherwise, we'll create a valid request header and data object to send
    // through `decode_hdr()`. Randomly generate a DDI request object with the
    // header and the random seed
    let encode_result: Result<Vec<u8>, String> =
        get_rand_ddi_request(input.request_header, input.request_seed);

    // it's possible that the randomly-generated request object didn't produced
    // an encoding error (one example: perhaps an invalid length was specified
    // for an `MborByteArray`). If that's the case, we'll return early
    if encode_result.is_err() {
        return Corpus::Keep;
    }

    // otherwise, if encoding succeeded, extract the encoded data and pass it
    // through the decoder
    let data: Vec<u8> = encode_result.unwrap();
    let mut decoder = DdiDecoder::new(data.as_slice(), true);
    let _result_hdr = decoder.decode_hdr::<DdiReqHdr>();
    Corpus::Keep
});

#[cfg(target_os = "windows")]
fn main() {}
