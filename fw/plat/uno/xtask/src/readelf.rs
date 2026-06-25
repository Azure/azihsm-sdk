// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware readelf command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Inspect firmware ELF headers with rust-readobj.
#[derive(Parser)]
#[clap(about = "Inspect firmware ELF headers with rust-readobj")]
pub struct Readelf {
    /// Extra flags passed to rust-readobj.
    #[clap(last = true)]
    args: Vec<String>,
}

impl Xtask for Readelf {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let elf = fw.elf.to_string_lossy().to_string();
        let mut extra = self.args;
        if extra.is_empty() {
            extra.push("--headers".into());
        }

        log::info!("Running rust-readobj...");
        cmd!(sh, "rust-readobj {extra...} {elf}").run()?;
        Ok(())
    }
}
