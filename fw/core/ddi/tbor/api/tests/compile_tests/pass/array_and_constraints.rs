// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: fixed-size array and length constraints.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x03)]
pub struct ArrayReq<'a> {
    nonce: [u8; 16],
    #[tbor(min_len = 1, max_len = 64)]
    tag: &'a [u8],
    #[tbor(align = 4, max_len = 256)]
    payload: &'a [u8],
}

fn main() {
    let nonce = [0u8; 16];
    let mut buf = [0u8; 256];
    let frame = ArrayReq::encode(&mut buf).unwrap()
        .nonce(&nonce).unwrap()
        .tag(b"hello").unwrap()
        .payload(b"data").unwrap()
        .finish();

    let view = ArrayReq::decode(frame.as_bytes()).unwrap();
    let _n: &[u8; 16] = view.nonce(); // type is &[u8; 16]
}
