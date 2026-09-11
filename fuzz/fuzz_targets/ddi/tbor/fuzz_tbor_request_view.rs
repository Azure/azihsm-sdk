// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "../../common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    common::run_request_view(data);
});
