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
pub struct FwPrecheck {}

impl Xtask for FwPrecheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running firmware precheck");

        let sh = xshell::Shell::new()?;
        sh.change_dir(ctx.root.join("fw").join("plat").join("uno"));
        cmd!(sh, "cargo xtask precheck").run()?;

        log::trace!("done firmware precheck");
        Ok(())
    }
}
