// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware cargo-bloat command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Analyze firmware binary size with cargo-bloat.
#[derive(Parser)]
#[clap(about = "Analyze firmware binary size with cargo-bloat")]
pub struct Bloat {
    /// Extra flags passed to cargo-bloat.
    #[clap(last = true)]
    args: Vec<String>,
}

impl Xtask for Bloat {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let _dir = sh.push_dir(&fw.fw_dir);
        let extra = self.args;

        log::info!("Running cargo-bloat...");
        cmd!(sh, "cargo +nightly bloat --release {extra...}").run()?;
        Ok(())
    }
}
