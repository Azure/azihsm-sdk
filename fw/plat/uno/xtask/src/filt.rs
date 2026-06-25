// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware symbol filtering command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// List firmware symbols demangled with rustfilt.
#[derive(Parser)]
#[clap(about = "List firmware symbols demangled with rustfilt")]
pub struct Filt {}

impl Xtask for Filt {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let elf = fw.elf.to_string_lossy().to_string();
        let quoted_elf = shell_quote(&elf);
        let pipe_cmd = format!("rust-nm --size-sort --reverse-sort {quoted_elf} | rustfilt");

        log::info!("Running rust-nm | rustfilt...");
        cmd!(sh, "sh -c {pipe_cmd}").run()?;
        Ok(())
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
