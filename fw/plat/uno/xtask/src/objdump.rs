// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware objdump command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Disassemble firmware with rust-objdump.
#[derive(Parser)]
#[clap(about = "Disassemble firmware with rust-objdump")]
pub struct Objdump {
    /// Extra flags passed to rust-objdump.
    #[clap(last = true)]
    args: Vec<String>,
}

impl Xtask for Objdump {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let elf = fw.elf.to_string_lossy().to_string();
        let mut extra = self.args;
        if extra.is_empty() {
            extra.push("--disassemble".into());
            extra.push("--demangle".into());
        }

        log::info!("Running rust-objdump...");
        cmd!(sh, "rust-objdump {extra...} {elf}").run()?;
        Ok(())
    }
}
