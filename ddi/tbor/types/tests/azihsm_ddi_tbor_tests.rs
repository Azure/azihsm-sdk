// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration test binary for `azihsm_ddi_tbor_types`.
//!
//! Backend selection is feature-gated; the same tests run across every
//! transport. Run with `--features emu` (in-process firmware),
//! `--features sock` (firmware behind a socket server), or
//! `--features mock` (transport-contract probes).
//!
//! With **no** feature enabled the crate falls through to the native
//! OS backend (`nix` on Linux / `win` on Windows), which drives real
//! silicon. Hardware-only smoke tests live under [`hw`].

#[cfg(any(feature = "emu", feature = "mock", feature = "sock"))]
pub mod harness;

pub mod commands;

#[cfg(not(any(feature = "emu", feature = "mock", feature = "sock")))]
pub mod hw;
