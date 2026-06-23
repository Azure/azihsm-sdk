// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware clippy command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Run clippy lints on firmware.
#[derive(Parser)]
#[clap(about = "Run clippy lints on firmware")]
pub struct Clippy {}

impl Xtask for Clippy {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;

        // Firmware workspace (nightly, thumb target).
        {
            let _dir = sh.push_dir(&fw.fw_dir);
            log::info!("Running clippy on firmware workspace...");
            cmd!(sh, "cargo +nightly clippy -- -D warnings").run()?;
        }

        // Top platform workspace (xtask + reggen + systemrdl, host target).
        {
            let _dir = sh.push_dir(&ctx.root);
            log::info!("Running clippy on platform workspace...");
            cmd!(sh, "cargo clippy --workspace -- -D warnings").run()?;
        }

        Ok(())
    }
}
