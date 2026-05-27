// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! This module contains two categories of resiliency tests:
//!
//! 1. **Fault-injection tests** (`res-fi` feature) — in the
//!    [`fault_injection`] sub-module. Each sub-module targets a
//!    specific API surface and uses the resiliency DDI device
//!    (`azihsm_ddi_mock`) to inject transient faults, verifying
//!    that the retry-with-backoff machinery recovers correctly.
//!
//! 2. **Stress tests** — in the [`stress`] sub-module. Multi-threaded
//!    tests that trigger real NSSRs via [`HsmPartition::reset`] while
//!    worker threads perform key operations concurrently. These do
//!    **not** require the `res-fi` feature.

mod helpers;

#[cfg(feature = "res-fi")]
mod fault_injection;

mod stress;
