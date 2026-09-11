// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_codec::RequestEncoder;
use common::EncoderTOCBuilders;
use common::FUZZ_REQ_BUF_SIZE;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    version: u8,
    opcode: u8,
    ops: Vec<EncoderTOCBuilders>,
}

fuzz_target!(|input: FuzzInput| {
    let mut buf = [0u8; FUZZ_REQ_BUF_SIZE];
    let encoder = RequestEncoder::new(&mut buf, input.version, input.opcode);
    let _ = common::run_encoder(encoder, &input.ops);
});
