// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to install cargo-nextest

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to install cargo-nextest
#[derive(Parser)]
#[clap(about = "Install cargo-nextest")]
pub struct InstallCargoNextest {}

impl Xtask for InstallCargoNextest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install cargo-nextest");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        cmd!(
            sh,
            "cargo {rust_toolchain...} install cargo-nextest --locked"
        )
        .quiet()
        .run()?;

        log::trace!("done install cargo-nextest");
        Ok(())
    }
}
