// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: skipping a required field should not compile.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x02)]
pub struct SkipReq {
    required_a: u8,
    required_b: u16,
    required_c: u8,
}

fn main() {
    let mut buf = [0u8; 64];
    // Try to skip required_b by jumping to required_c.
    let _ = SkipReq::encode(&mut buf).unwrap()
        .required_a(1).unwrap()
        .required_c(3).unwrap() // ERROR: cannot skip required field required_b
        .finish();
}
