// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use common::{EncoderTOCBuilders, FUZZ_BUF_SIZE};
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use azihsm_ddi_tbor_codec::RequestEncoder;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    version: u8,
    opcode: u8,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut buf = [0u8; FUZZ_BUF_SIZE];
    let encoder = RequestEncoder::new(&mut buf, input.version, input.opcode);
    common::run_encoder(encoder, &input.ops);
});
