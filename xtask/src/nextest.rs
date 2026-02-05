// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run nextest

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run nextest
#[derive(Parser)]
#[clap(about = "Run nextest")]
pub struct Nextest {
    /// Features to include in nextest run
    #[clap(long)]
    pub features: Option<String>,

    /// Package argument to run nextest command with
    #[clap(long)]
    pub package: Option<String>,

    /// Whether to include --no-default-features
    #[clap(long)]
    pub no_default_features: bool,

    /// Test filterset (see https://nexte.st/docs/filtersets)
    #[clap(long, short = 'E')]
    pub filterset: Option<String>,
}

impl Xtask for Nextest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running nextest");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // Check nextest version
        let rust_toolchain_version = rust_toolchain.clone();
        cmd!(sh, "cargo {rust_toolchain_version...} nextest --version")
            .quiet()
            .run()?;

        // convert xtask parameters into cargo command arguments
        let mut command_args = Vec::new();
        let mut features_vec = Vec::new();
        if self.features.is_some() {
            features_vec.push(self.features.unwrap_or_default());
        }
        let features_val;
        if !features_vec.is_empty() {
            command_args.push("--features");
            features_val = features_vec.join(",");
            command_args.push(&features_val);
        }
        let package_val = self.package.clone().unwrap_or_default();
        if self.package.is_some() {
            command_args.push("--package");
            command_args.push(&package_val);
        }
        if self.no_default_features {
            command_args.push("--no-default-features");
        }
        let filterset_val = self.filterset.clone().unwrap_or_default();
        if self.filterset.is_some() {
            command_args.push("--filterset");
            command_args.push(&filterset_val);
        }

        cmd!(
            sh,
            "cargo {rust_toolchain...} nextest run --no-fail-fast {command_args...}"
        )
        .quiet()
        .run()?;

        log::trace!("done nextest");
        Ok(())
    }
}
