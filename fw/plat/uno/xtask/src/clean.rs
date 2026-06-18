// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware clean command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Clean firmware build artifacts.
#[derive(Parser)]
#[clap(about = "Clean firmware build artifacts")]
pub struct Clean {}

impl Xtask for Clean {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let _dir = sh.push_dir(&fw.fw_dir);

        log::info!("Cleaning firmware...");
        cmd!(sh, "cargo +nightly clean").run()?;
        Ok(())
    }
}
