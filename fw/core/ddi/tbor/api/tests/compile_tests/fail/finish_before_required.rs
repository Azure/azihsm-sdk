// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: finish() before all required fields are set should not compile.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x03)]
pub struct EarlyFinish {
    required: u8,
    optional: Option<u16>,
}

fn main() {
    let mut buf = [0u8; 64];
    // ERROR: finish() is not available on State0 because `required` is not optional.
    let _ = EarlyFinish::encode(&mut buf).unwrap()
        .finish();
}
