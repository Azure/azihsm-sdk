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

        // The engine crates require a system OpenSSL 1.1.x at build-script
        // time, which standard runners/hosts don't have.  They are linted
        // in the Engine matrix workflow instead.
        const DEFAULT_EXCLUDES: &[&str] =
            &["azihsm_engine", "openssl-engine", "openssl-sys-engine"];

        let mut exclude_args: Vec<String> = Vec::new();

        for crate_name in DEFAULT_EXCLUDES
            .iter()
            .map(|s| s.to_string())
            .chain(self.exclude.iter().cloned())
        {
            exclude_args.push("--exclude".to_string());
            exclude_args.push(crate_name);
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
