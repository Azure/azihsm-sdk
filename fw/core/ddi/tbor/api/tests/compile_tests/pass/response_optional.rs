// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Valid: response with optional and FIPS flag.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(response)]
pub struct MyResp<'a> {
    #[tbor(max_len = 256)]
    data: &'a [u8],
    #[tbor(max_len = 256)]
    opt_tag: Option<&'a [u8]>,
}

fn main() {
    let mut buf = [0u8; 256];

    // With tag.
    let _ = MyResp::encode(&mut buf, 0, true).unwrap()
        .data(b"ciphertext").unwrap()
        .opt_tag(Some(b"tag")).unwrap()
        .finish();

    // Without tag — early finish.
    let _ = MyResp::encode(&mut buf, 0, false).unwrap()
        .data(b"ciphertext").unwrap()
        .finish();
}
