// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "linux", no_main)]

#[cfg(target_os = "linux")]
#[path = "../common.rs"]
mod common;

#[cfg(target_os = "linux")]
use arbitrary::Arbitrary;
#[cfg(target_os = "linux")]
use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
use crate::common::*;

#[cfg(target_os = "linux")]
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Randomized seed for deterministically generating random DDI request
    /// command objects.
    rand_seed: u64,

    /// Vector containing DDI request command types, with which the `exec_op()`
    /// function will be called.
    reqs: Vec<TestDdiReqs>,
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: FuzzInput| {
    fuzz_cmd_reqs(input.reqs, input.rand_seed);
});

#[cfg(target_os = "windows")]
fn main() {}
