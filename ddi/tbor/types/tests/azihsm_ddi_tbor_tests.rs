// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware) or with
//! **no** feature (native OS backend — `nix` on Linux / `win` on
//! Windows — for on-silicon test runs).
//!
//! `mock` and `sock` disable the whole harness + `commands` tree:
//! mock rejects TBOR at the transport layer, and sock's `erase` is a
//! stub, so command-level integration tests are meaningless there.
//! Under `mock` or `sock` this binary compiles the crate only and
//! runs zero tests.

#[cfg(not(any(feature = "mock", feature = "sock")))]
pub mod harness;

#[cfg(not(any(feature = "mock", feature = "sock")))]
pub mod commands;
