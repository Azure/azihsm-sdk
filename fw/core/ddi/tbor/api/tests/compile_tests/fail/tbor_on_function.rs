// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use azihsm_fw_ddi_tbor_api::tbor;
#[tbor(opcode = 0x01)]
fn bad() {}
fn main() {}
