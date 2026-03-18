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

        // Set environment variable for llvm-cov to generate .profraw files
        //sh.set_var("LLVM_PROFILE_FILE", "coverage-%p-%m.profraw");
        //sh.set_var("LLVM_COV", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\Llvm\\bin\\llvm-cov.exe");
        //sh.set_var("LLVM_PROFDATA", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\Llvm\\bin\\llvm-profdata.exe");
        //sh.set_var("RUSTFLAGS", "-C link-dead-code");

        sh.set_var("LLVM_COV", "C:\\Users\\v-davidz\\.rustup\\toolchains\\1.93-x86_64-pc-windows-msvc\\lib\\rustlib\\x86_64-pc-windows-msvc\\bin\\llvm-cov.exe");
        sh.set_var("LLVM_PROFDATA", "C:\\Users\\v-davidz\\.rustup\\toolchains\\1.93-x86_64-pc-windows-msvc\\lib\\rustlib\\x86_64-pc-windows-msvc\\bin\\llvm-profdata.exe");

        // sanity check
        cmd!(sh, "cargo llvm-cov show-env").quiet().run()?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --include-ffi --no-fail-fast --features mock --profile ci-mock --workspace --exclude integration-tests"
        )
        .run()?;

        // Check for/create reports directory
        let reports_dir = ctx.root.join("target").join("reports");
        if !reports_dir.exists() {
            log::info!("Creating reports directory at {}", reports_dir.display());
            std::fs::create_dir_all(&reports_dir)?;
        }

        // Generate cobertura report
        log::info!("Generating cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path ./target/reports/cobertura_sdk.xml --include-ffi"
        ).run()?;

        // Generate json report
        log::info!("Generating json report");
        cmd!(
            sh,
            "cargo llvm-cov report --json --summary-only --output-path ./target/reports/sdk-cov.json --include-ffi"
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, " cargo llvm-cov report --html --output-dir ./target/reports/sdk-cov/ --include-ffi").run()?;

        log::info!("Code coverage completed successfully");

        Ok(())
    }
}
