// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run create directories

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run create directories
#[derive(Parser)]
#[clap(about = "Install cargo-fuzz")]
pub struct InstallCargoFuzz {}

impl Xtask for InstallCargoFuzz {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install cargo-fuzz");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        cmd!(sh, "cargo {rust_toolchain...} install cargo-fuzz")
            .quiet()
            .run()?;

        log::trace!("done install cargo-fuzz");
        Ok(())
    }
}
