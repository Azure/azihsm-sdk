// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: calling a field twice should not compile.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x06)]
pub struct DupReq {
    a: u8,
    b: u16,
}

fn main() {
    let mut buf = [0u8; 64];
    let _ = DupReq::encode(&mut buf).unwrap()
        .a(1).unwrap()
        .a(2).unwrap() // ERROR: `a` not available on State1
        .b(3).unwrap()
        .finish();
}
