// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: wrong type for a field should not compile.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x04)]
pub struct TypeReq {
    value: u8,
}

fn main() {
    let mut buf = [0u8; 64];
    let _ = TypeReq::encode(&mut buf).unwrap()
        .value("not a u8").unwrap() // ERROR: expected u8
        .finish();
}
