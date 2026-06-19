// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Pass: #[tbor] on a struct with no fields. The body wire-encodes as a
// single synthetic `None` TOC placeholder, and the generated decoder
// validates that placeholder is present.
#![allow(unsafe_code)]
use azihsm_fw_ddi_tbor_api::tbor;
use azihsm_fw_hsm_pal_traits::DmaBuf;

fn brand(b: &[u8]) -> &DmaBuf {
    unsafe { DmaBuf::from_raw(b) }
}

#[tbor(opcode = 0x01)]
pub struct EmptyReq {}

fn main() {
    let mut buf = [0u8; 16];
    let frame = EmptyReq::encode(&mut buf).expect("encode").finish();
    let bytes = frame.as_bytes();
    // 4-byte header + 1 TOC entry (4 bytes) = 8 bytes total.
    assert_eq!(bytes.len(), 8);
    EmptyReq::decode(brand(bytes)).expect("decode");
}
