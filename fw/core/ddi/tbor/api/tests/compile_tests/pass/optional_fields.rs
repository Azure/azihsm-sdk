// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: optional fields with early finish and skip-ahead.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x02)]
pub struct OptReq {
    required: u8,
    opt_a: Option<u16>,
    opt_b: Option<u8>,
}

fn main() {
    let mut buf = [0u8; 64];

    // Set all fields.
    let _ = OptReq::encode(&mut buf).unwrap()
        .required(1).unwrap()
        .opt_a(Some(2)).unwrap()
        .opt_b(Some(3)).unwrap()
        .finish();

    // Early finish — skip trailing optionals.
    let _ = OptReq::encode(&mut buf).unwrap()
        .required(1).unwrap()
        .finish();

    // Skip intermediate optional, jump to opt_b.
    let _ = OptReq::encode(&mut buf).unwrap()
        .required(1).unwrap()
        .opt_b(Some(3)).unwrap()
        .finish();

    // Set opt_a with None explicitly.
    let _ = OptReq::encode(&mut buf).unwrap()
        .required(1).unwrap()
        .opt_a(None).unwrap()
        .opt_b(Some(3)).unwrap()
        .finish();
}
