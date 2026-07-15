// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

mod algo;
mod partition_tests;
mod resiliency;
#[cfg(feature = "res-test")]
mod resiliency_tests;
mod session_tests;
mod utils;

#[cfg(feature = "emu")]
mod emu_helpers;
#[cfg(feature = "emu")]
mod partition_ex_tests;
#[cfg(feature = "emu")]
mod sealing_ex_tests;
#[cfg(feature = "emu")]
mod session_ex_tests;

use azihsm_api::*;
use azihsm_api_tests_macro::*;
