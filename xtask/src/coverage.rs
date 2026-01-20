// Copyright (C) Microsoft Corporation. All rights reserved.

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

        // Set default value for CARGO_TARGET_DIR if not set
        if sh.var("CARGO_TARGET_DIR").is_err() {
            let target_dir = ctx.root.join("target");
            log::info!(
                "Env Variable CARGO_TARGET_DIR not set, defaulting to {}",
                target_dir.display()
            );
            sh.set_var("CARGO_TARGET_DIR", &target_dir);
        }

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(sh, "cargo llvm-cov nextest --features mock").run()?;

        // Generate cobertura report
        log::info!("Gathering cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path .\\target\\reports\\cobertura_sdk.xml --ignore-filename-regex \"xtask\""
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, " cargo llvm-cov report --html --output-dir .\\target\\reports\\sdk-cov\\ --ignore-filename-regex \"xtask\"").run()?;

        log::info!("Code coverage completed successfully");
        Ok(())
    }
}
