// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use azihsm_fw_ddi_tbor_api::tbor;
#[tbor(opcode = "hello")]
pub struct BadOpcode { a: u8 }
fn main() {}
