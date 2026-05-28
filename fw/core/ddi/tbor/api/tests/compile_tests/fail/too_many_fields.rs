// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use azihsm_fw_ddi_tbor_api::tbor;
#[tbor(opcode = 0x01)]
pub struct TooMany {
    f01: u8, f02: u8, f03: u8, f04: u8, f05: u8, f06: u8, f07: u8, f08: u8,
    f09: u8, f10: u8, f11: u8, f12: u8, f13: u8, f14: u8, f15: u8, f16: u8,
    f17: u8, f18: u8, f19: u8, f20: u8, f21: u8, f22: u8, f23: u8, f24: u8,
    f25: u8, f26: u8, f27: u8, f28: u8, f29: u8, f30: u8, f31: u8, f32: u8,
    f33: u8,
}
fn main() {}
