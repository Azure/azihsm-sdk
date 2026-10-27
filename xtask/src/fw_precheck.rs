// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run firmware precheck

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run firmware precheck
#[derive(Parser)]
#[clap(about = "Run firmware precheck")]
pub struct FwPrecheck {
    /// Skip `cargo audit` (useful offline).
    #[clap(long)]
    pub skip_audit: bool,
}

impl Xtask for FwPrecheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running firmware precheck");

        let sh = xshell::Shell::new()?;
        sh.change_dir(ctx.root.join("fw").join("plat").join("uno"));
        let mut command = cmd!(sh, "cargo xtask precheck");
        if self.skip_audit {
            command = command.arg("--skip-audit");
        }
        command.run()?;

        log::trace!("done firmware precheck");
        Ok(())
    }
}
