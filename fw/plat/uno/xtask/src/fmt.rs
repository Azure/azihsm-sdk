// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware formatting command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Run formatting checks on firmware.
#[derive(Parser)]
#[clap(about = "Run formatting checks on firmware")]
pub struct Fmt {
    /// Attempt to fix formatting issues.
    #[clap(long)]
    pub fix: bool,
}

impl Xtask for Fmt {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let fmt_check = (!self.fix).then_some("--check");

        // Firmware workspace (nightly).
        {
            let _dir = sh.push_dir(&fw.fw_dir);
            log::info!("Running fmt on firmware workspace...");
            cmd!(sh, "cargo +nightly fmt -- {fmt_check...}").run()?;
        }

        // Top platform workspace (xtask + reggen + systemrdl).
        {
            let _dir = sh.push_dir(&ctx.root);
            log::info!("Running fmt on platform workspace...");
            cmd!(sh, "cargo +nightly fmt --all -- {fmt_check...}").run()?;
        }

        Ok(())
    }
}
