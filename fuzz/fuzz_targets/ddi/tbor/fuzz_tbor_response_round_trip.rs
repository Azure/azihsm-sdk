// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_codec::ResponseEncoder;
use common::EncoderTOCBuilders;
use common::FUZZ_BUF_SIZE;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    version: u8,
    status: u32,
    fips_approved: bool,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut buf = [0u8; FUZZ_BUF_SIZE];
    let encoder = ResponseEncoder::new(&mut buf, input.version, input.status, input.fips_approved);
    if let Some(encoded) = common::run_encoder(encoder, &input.ops) {
        common::run_response_view(encoded);
    }
});
