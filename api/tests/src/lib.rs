// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

// The MBOR-backed suites drive the legacy command surface, which the
// `mock` simulator implements but the FW-core `emu` backend does not.
// Exclude them from an `emu` build so `-F emu` runs only the TBOR
// integration tests; `mock`/default builds are unchanged.
#[cfg(not(feature = "emu"))]
mod algo;
#[cfg(not(feature = "emu"))]
mod partition_tests;
#[cfg(not(feature = "emu"))]
mod resiliency;
#[cfg(all(feature = "res-test", not(feature = "emu")))]
mod resiliency_tests;
#[cfg(not(feature = "emu"))]
mod session_tests;
#[cfg(not(feature = "emu"))]
mod utils;

#[cfg(feature = "emu")]
mod emu_helpers;
#[cfg(feature = "emu")]
mod partition_ex_tests;
#[cfg(feature = "emu")]
mod session_ex_tests;

#[cfg(not(feature = "emu"))]
use azihsm_api::*;
#[cfg(not(feature = "emu"))]
use azihsm_api_tests_macro::*;
