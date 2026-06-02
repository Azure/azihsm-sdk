// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests.
///
/// Currently a no-op. The provider integration test passes (CLI, CAPI,
/// nginx) are temporarily disabled while the OpenSSL provider build
/// coupling with `libazihsm_api_native` is being reworked. The command
/// remains in the xtask surface so CI / scripted invocations stay
/// stable; it logs a skip notice and returns success.
///
/// Re-enable by restoring the nextest invocations in this file once
/// the build coupling rework lands.
#[derive(Parser)]
#[clap(about = "Run Integration Tests (currently disabled)")]
pub struct IntegrationTest {}

impl Xtask for IntegrationTest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::warn!(
            "skipping provider integration tests: temporarily disabled \
             while OpenSSL provider build coupling with libazihsm_api_native \
             is reworked. Re-enable by restoring the nextest invocations in \
             xtask/src/integration_tests.rs once the rework lands."
        );
        Ok(())
    }
}
