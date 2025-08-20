// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific clippy checks

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific clippy checks
#[derive(Parser)]
#[clap(about = "Run tests")]
pub struct Test {}

impl Xtask for Test {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running test");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        cmd!(
            sh,
            "cargo {rust_toolchain...} test --features mock,testhooks,use-symcrypt -- --test-threads=1"
        )
        .quiet()
        .run()?;

        log::trace!("done test");
        Ok(())
    }
}
