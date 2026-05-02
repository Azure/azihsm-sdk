// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: unsupported field type.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct BadType {
    value: f32,
}

fn main() {}
