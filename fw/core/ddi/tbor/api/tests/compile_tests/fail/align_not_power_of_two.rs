// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: align must be a power of two.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct BadAlignValue<'a> {
    #[tbor(align = 3)]
    data: &'a [u8],
}

fn main() {}
