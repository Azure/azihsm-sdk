// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: min_len/max_len on non-buffer type.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct BadConstraint {
    #[tbor(min_len = 1)]
    value: u32,
}

fn main() {}
