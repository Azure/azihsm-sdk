// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware),
//! `--features sock` (firmware behind a socket server), or with
//! **no** feature (native OS backend — `nix` on Linux / `win` on
//! Windows — for on-silicon test runs).
//!
//! `mock` disables the whole harness + `commands` tree: mock rejects
//! TBOR at the transport layer, so command-level integration tests
//! are meaningless there. Under `--features mock` this binary
//! compiles the crate only and runs zero tests.

#[cfg(not(feature = "mock"))]
pub mod harness;

#[cfg(not(feature = "mock"))]
pub mod commands;
