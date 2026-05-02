// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: basic request with scalar fields.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct BasicReq {
    a: u8,
    b: u16,
}

fn main() {
    let mut buf = [0u8; 64];
    let frame = BasicReq::encode(&mut buf).unwrap()
        .a(1).unwrap()
        .b(2).unwrap()
        .finish();
    let _ = BasicReq::decode(frame.as_bytes()).unwrap();
}
