// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

mod algo;
mod partition_tests;
#[cfg(any(feature = "mock", feature = "res-test"))]
mod resiliency;
#[cfg(feature = "res-test")]
mod resiliency_tests;
mod session_tests;
mod utils;

use azihsm_api::*;
use azihsm_api_tests_macro::*;
