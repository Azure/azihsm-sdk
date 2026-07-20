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
//! silicon. Hardware smoke tests that still use the standalone
//! [`hw::hw_test`] closure fixture live under [`hw`]; individual
//! `commands/*` files migrated to the `harness::Ctx` alias (see
//! `commands::api_rev`) additionally compile under `--features
//! hw-tests` and run against the same silicon backend through the
//! shared per-test fixture.

#[cfg(any(feature = "emu", feature = "mock", feature = "sock", feature = "hw-tests"))]
pub mod harness;

pub mod commands;

#[cfg(feature = "hw-tests")]
pub mod hw;
