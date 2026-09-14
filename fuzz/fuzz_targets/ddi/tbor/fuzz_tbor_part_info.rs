// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

#[path = "../../common.rs"]
mod common;

use azihsm_ddi_tbor_types::TborPartInfoReq;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|_input: &[u8]| {
    let dev = common::open_emu_dev();
    let req = TborPartInfoReq;
    common::fuzz_exec_op_tbor(&dev, &req);
});
