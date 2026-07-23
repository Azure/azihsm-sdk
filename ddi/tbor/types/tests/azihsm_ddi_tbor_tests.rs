// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware),
//! `--features sock` (firmware behind a socket server), or
//! `--features mock` (transport-contract probes). With **no** feature
//! enabled the crate falls through to the native OS backend (`nix`
//! on Linux / `win` on Windows) for on-silicon test runs.
//!
//! `mock` disables the whole `commands` tree — mock rejects TBOR at
//! the transport layer, so command-level integration tests are
//! meaningless there. Under `mock` this binary compiles the harness
//! only and runs zero tests.

pub mod harness;

#[cfg(not(feature = "mock"))]
pub mod commands;
