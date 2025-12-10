// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run rust tests

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run rust tests
#[derive(Parser)]
#[clap(about = "Run rust tests")]
pub struct Test {}

impl Xtask for Test {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running rust tests");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        cmd!(sh, "cargo {rust_toolchain...} test --all-targets")
            .quiet()
            .run()?;

        log::trace!("done tests");
        Ok(())
    }
}
