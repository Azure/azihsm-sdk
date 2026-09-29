// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod cbc_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod gcm_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod key_prop_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod key_tests;
#[cfg(not(feature = "session-ex-tests"))]
mod nist_tests;

#[cfg(not(feature = "session-ex-tests"))]
mod xts_tests;

use super::*;

pub mod common;
