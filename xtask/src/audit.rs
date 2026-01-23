// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific audit checks

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific audit checks
#[derive(Parser)]
#[clap(about = "Run various audit checks")]
pub struct Audit {}

impl Xtask for Audit {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running audit");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // Check audit version
        let rust_toolchain_version = rust_toolchain.clone();
        cmd!(sh, "cargo {rust_toolchain_version...} audit --version")
            .quiet()
            .run()?;

        cmd!(sh, "cargo {rust_toolchain...} audit --deny warnings")
            .quiet()
            .run()?;

        log::trace!("done audit");
        Ok(())
    }
}
