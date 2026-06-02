// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: calling fields out of order should not compile.
// Field `b` must come after `a` in the typestate chain.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct OrderReq {
    a: u8,
    b: u16,
}

fn main() {
    let mut buf = [0u8; 64];
    let _ = OrderReq::encode(&mut buf).unwrap()
        .b(2).unwrap()  // ERROR: b is not available on State0
        .a(1).unwrap()
        .finish();
}
