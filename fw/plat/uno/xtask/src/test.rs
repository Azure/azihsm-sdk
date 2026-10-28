// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware test command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Host target used to run firmware unit tests.
///
/// The firmware workspace builds for `thumbv7em-none-eabi` by default (see
/// `fw/.cargo/config.toml`), which cannot host a test harness. Unit tests are
/// therefore compiled and executed for the host target instead.
const HOST_TARGET: &str = "x86_64-unknown-linux-gnu";

/// Run firmware unit tests on the host target.
#[derive(Parser)]
#[clap(about = "Run firmware unit tests (host target)")]
pub struct Test {
    /// Only test the specified package(s). Defaults to the whole workspace.
    #[clap(short, long)]
    pub package: Vec<String>,

    /// Build and test in release mode.
    #[clap(long)]
    pub release: bool,

    /// Test with the given features enabled.
    #[clap(long)]
    pub features: Option<String>,

    /// Test without the crate's default features.
    #[clap(long)]
    pub no_default_features: bool,

    /// Arguments passed through to the test harness (e.g. a test name filter).
    #[clap(trailing_var_arg = true)]
    pub args: Vec<String>,
}

impl Xtask for Test {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let _dir = sh.push_dir(&fw.fw_dir);

        let mut args = vec!["test", "--target", HOST_TARGET];

        if self.package.is_empty() {
            args.push("--workspace");
        } else {
            for package in &self.package {
                args.push("--package");
                args.push(package);
            }
        }

        if self.release {
            args.push("--release");
        }

        if self.no_default_features {
            args.push("--no-default-features");
        }

        if let Some(features) = self
            .features
            .as_ref()
            .filter(|features| !features.trim().is_empty())
        {
            args.push("--features");
            args.push(features);
        }

        if !self.args.is_empty() {
            args.push("--");
            for arg in &self.args {
                args.push(arg);
            }
        }

        log::info!("Running firmware tests on {HOST_TARGET}...");
        cmd!(sh, "cargo {args...}").run()?;
        log::info!("Firmware tests complete.");
        Ok(())
    }
}
