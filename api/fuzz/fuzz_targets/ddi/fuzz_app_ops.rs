// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg_attr(target_os = "linux", no_main)]

#[cfg(target_os = "linux")]
#[path = "../common.rs"]
mod common;

#[cfg(target_os = "linux")]
use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
use crate::common::*;

#[cfg(target_os = "linux")]
fuzz_target!(|ops: Vec<TestAppOps>| {
    fuzz_app_ops(ops);
});

#[cfg(target_os = "windows")]
fn main() {}
