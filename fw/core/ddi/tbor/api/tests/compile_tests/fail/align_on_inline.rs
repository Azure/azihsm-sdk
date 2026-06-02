// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: align on an inline type (u8 doesn't use data section).
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct BadAlign {
    #[tbor(align = 4)]
    value: u8,
}

fn main() {}
