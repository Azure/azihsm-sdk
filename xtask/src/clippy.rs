// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific clippy checks

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific clippy checks
#[derive(Parser)]
#[clap(about = "Run various clippy checks")]
pub struct Clippy {
    /// Crates to exclude from clippy (e.g. crates with heavyweight build scripts)
    #[clap(long)]
    pub exclude: Vec<String>,
}

impl Xtask for Clippy {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running clippy");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // Check Clippy version
        let rust_toolchain_version = rust_toolchain.clone();
        cmd!(sh, "cargo {rust_toolchain_version...} clippy --version")
            .quiet()
            .run()?;

        let mut exclude_args: Vec<String> = Vec::new();

        if !self.exclude.is_empty() {
            for crate_name in &self.exclude {
                exclude_args.push("--exclude".to_string());
                exclude_args.push(crate_name.clone());
            }
        }

        cmd!(
            sh,
            "cargo {rust_toolchain...} clippy --workspace --all-targets {exclude_args...} -- -D warnings"
        )
        .quiet()
        .run()?;

        log::trace!("done clippy");
        Ok(())
    }
}
