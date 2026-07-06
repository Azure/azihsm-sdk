// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware size analysis command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Show firmware section sizes with rust-size.
#[derive(Parser)]
#[clap(about = "Show firmware section sizes with rust-size")]
pub struct Size {
    /// Extra flags passed to rust-size.
    #[clap(last = true)]
    args: Vec<String>,
}

impl Xtask for Size {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let elf = fw.elf.to_string_lossy().to_string();
        let extra = self.args;

        log::info!("Running rust-size...");
        cmd!(sh, "rust-size {extra...} {elf}").run()?;
        Ok(())
    }
}
