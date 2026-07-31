// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::{EncoderTOCBuilders, FUZZ_BUF_SIZE};
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use azihsm_ddi_tbor_codec::ResponseEncoder;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    version: u8,
    status: u32,
    fips_approved: bool,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut buf = [0u8; FUZZ_BUF_SIZE];
    let encoder =
        ResponseEncoder::new(&mut buf, input.version, input.status, input.fips_approved);
    common::run_encoder(encoder, &input.ops);
});
