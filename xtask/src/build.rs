// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run build

use clap::Parser;
use xshell::cmd;

use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run build
#[derive(Parser)]
#[clap(about = "Run build")]
pub struct Build {
    /// Whether to include --tests argument
    #[clap(long)]
    pub tests: bool,

    /// Whether to include --all-targets argument
    #[clap(long)]
    pub all_targets: bool,

    /// Whether to include --release argument
    #[clap(long)]
    pub release: bool,

    /// Features to include in build
    #[clap(long)]
    pub features: Option<String>,

    /// Package to build
    #[clap(long)]
    pub package: Option<String>,
}

impl Xtask for Build {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running build");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let target_dir = common::target_dir()?;

        // convert xtask parameters into cargo command arguments
        let mut command_args = Vec::new();
        if self.tests {
            command_args.push("--tests");
        }
        if self.all_targets {
            command_args.push("--all-targets");
        }
        if self.release {
            command_args.push("--release");
        }
        command_args.push("--features");
        let features = self.features.unwrap_or_default().clone();
        command_args.push(features.as_str());
        if self.package.is_some() {
            command_args.push("--package");
        }
        let package_val = self.package.clone().unwrap_or_default();
        if self.package.is_some() {
            command_args.push(&package_val);
        }
        command_args.push("--target-dir");
        command_args.push(target_dir.to_str().unwrap());

        // elevate warnings to errors for build
        std::env::set_var("RUSTFLAGS", "-D warnings");

        cmd!(sh, "cargo {rust_toolchain...} build {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done build");
        Ok(())
    }
}
