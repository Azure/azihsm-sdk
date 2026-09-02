// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_types::TborSessionCloseReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    session_id: u16,
}

fuzz_target!(|input: FuzzInput| {
    let dev = common::open_emu_dev();
    let req = TborSessionCloseReq {
        session_id: input.session_id,
    };
    common::fuzz_exec_op_tbor(&dev, &req);
});
