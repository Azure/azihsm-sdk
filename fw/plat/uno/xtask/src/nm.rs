// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware symbol listing command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// List firmware symbols with rust-nm.
#[derive(Parser)]
#[clap(about = "List firmware symbols with rust-nm")]
pub struct Nm {
    /// Extra flags passed to rust-nm.
    #[clap(last = true)]
    args: Vec<String>,
}

impl Xtask for Nm {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let elf = fw.elf.to_string_lossy().to_string();
        let mut extra = self.args;
        if extra.is_empty() {
            extra.push("--demangle".into());
            extra.push("--size-sort".into());
            extra.push("--reverse-sort".into());
        }

        log::info!("Running rust-nm...");
        cmd!(sh, "rust-nm {extra...} {elf}").run()?;
        Ok(())
    }
}
