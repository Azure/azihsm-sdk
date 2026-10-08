// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![cfg(test)]

#[cfg(all(feature = "mock", feature = "session-ex-tests"))]
compile_error!("features `mock` and `session-ex-tests` cannot be enabled together");

mod algo;
#[cfg(not(feature = "session-ex-tests"))]
mod partition_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod resiliency;
#[cfg(all(feature = "res-test", not(feature = "session-ex-tests")))]
mod resiliency_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod session_tests;
mod utils;
#[cfg(feature = "sock")]
mod vsocksrv_session_tests;

#[cfg(all(feature = "session-ex-tests", not(feature = "mock")))]
mod partition_ex_tests;
#[cfg(all(feature = "session-ex-tests", not(feature = "mock")))]
mod sd;
#[cfg(all(feature = "session-ex-tests", not(feature = "mock")))]
mod session_ex_tests;

use azihsm_api::*;
use azihsm_api_tests_macro::*;
