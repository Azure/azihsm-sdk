// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: basic request with scalar fields.
#![allow(unsafe_code)]
use azihsm_fw_ddi_tbor_api::tbor;
use azihsm_fw_hsm_pal_traits::DmaBuf;

fn brand(b: &[u8]) -> &DmaBuf {
    unsafe { DmaBuf::from_raw(b) }
}

#[tbor(opcode = 0x01)]
pub struct BasicReq {
    a: u8,
    b: u16,
}

fn main() {
    let mut buf = [0u8; 64];
    let frame = BasicReq::encode(&mut buf)
        .unwrap()
        .a(1)
        .unwrap()
        .b(2)
        .unwrap()
        .finish();
    let _ = BasicReq::decode(brand(frame.as_bytes())).unwrap();
}
