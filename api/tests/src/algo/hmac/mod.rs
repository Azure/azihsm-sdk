// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod hmac_tests;
// HMAC key generation is a TBOR-only (V2) capability that a real backend
// (emu or hardware) provides; gate the module out for the mock backend.
#[cfg(not(feature = "mock"))]
mod key_gen_tests;
mod key_prop_tests;

use super::*;
