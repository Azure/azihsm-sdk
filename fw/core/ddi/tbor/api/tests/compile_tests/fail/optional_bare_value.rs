// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: passing bare value to optional field should not compile.
// Optional fields require Option<T>.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x05)]
pub struct OptTypeReq {
    required: u8,
    opt: Option<u16>,
}

fn main() {
    let mut buf = [0u8; 64];
    let _ = OptTypeReq::encode(&mut buf).unwrap()
        .required(1).unwrap()
        .opt(42u16).unwrap() // ERROR: expected Option<u16>, got u16
        .finish();
}
