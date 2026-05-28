// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use azihsm_fw_ddi_tbor_api::tbor;
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[tbor]
pub enum BadEnum { A = 1, B = 2 }
fn main() {}
