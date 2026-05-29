// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use azihsm_fw_ddi_tbor_api::tbor;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[tbor]
#[repr(u8)]
pub enum BadEnum { A, B }
fn main() {}
