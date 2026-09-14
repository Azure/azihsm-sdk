// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_types::TborGetCertChainInfoReq;
use libfuzzer_sys::arbitrary;
use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    slot_id: u8,
}

fuzz_target!(|input: FuzzInput| {
    let dev = common::open_emu_dev();
    let req = TborGetCertChainInfoReq {
        slot_id: input.slot_id,
    };
    common::fuzz_exec_op_tbor(&dev, &req);
});
