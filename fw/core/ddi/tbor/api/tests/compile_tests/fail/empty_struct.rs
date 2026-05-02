// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// Fail: #[tbor] struct with no fields.
use azihsm_fw_ddi_tbor_api::tbor;

#[tbor(opcode = 0x01)]
pub struct EmptyReq {}

fn main() {}
