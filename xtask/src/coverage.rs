// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run code coverage

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run code coverage
#[derive(Parser)]
#[clap(about = "Run code coverage using cargo llvm-cov")]
pub struct Coverage {}

impl Xtask for Coverage {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running code coverage");

        let sh = xshell::Shell::new()?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --no-fail-fast --features mock --profile ci-mock -- --skip algo::ecc::ecdh_tests"
        )
        .run()?;

        // Check for/create reports directory
        let reports_dir = ctx.root.join("target").join("reports");
        if !reports_dir.exists() {
            log::info!("Creating reports directory at {}", reports_dir.display());
            std::fs::create_dir_all(&reports_dir)?;
        }

        // Generate cobertura report
        log::info!("Gathering cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path ./target/reports/cobertura_sdk.xml --ignore-filename-regex xtask*"
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, " cargo llvm-cov report --html --output-dir ./target/reports/sdk-cov/ --ignore-filename-regex xtask*").run()?;

        log::info!("Code coverage completed successfully");
        Ok(())
    }
}
