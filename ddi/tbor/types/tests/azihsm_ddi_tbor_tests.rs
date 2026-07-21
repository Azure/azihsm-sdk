// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware),
//! `--features sock` (firmware behind a socket server), or
//! `--features mock` (transport-contract probes). `--features
//! hw-tests` compiles the same `commands/*` tests against real
//! silicon through the shared [`harness::Ctx`] alias.
//!
//! With **no** feature enabled the crate falls through to the native
//! OS backend (`nix` on Linux / `win` on Windows) for build-only
//! checks; no tests are compiled in that mode.

#[cfg(any(
    feature = "emu",
    feature = "mock",
    feature = "sock",
    feature = "hw-tests"
))]
pub mod harness;

pub mod commands;
