// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests
#[derive(Parser)]
#[clap(about = "Run Integration Tests")]
pub struct IntegrationTest {}

impl Xtask for IntegrationTest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("start testing");

        let sh = xshell::Shell::new()?;

        // Run the integration tests in the integration-tests package
        log::info!("Running integration tests...");
        cmd!(sh, "cargo test -p integration-tests --features integration").run()?;

        log::trace!("end testing");
        Ok(())
    }
}
