// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific formatting checks

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific formatting checks
#[derive(Parser)]
#[clap(about = "Run various formatting checks")]
pub struct Fmt {
    /// Attempt to fix any formatting issues
    #[clap(long)]
    pub fix: bool,

    /// Override toolchain to use for formatting
    #[clap(long)]
    pub toolchain: Option<String>,
}

impl Xtask for Fmt {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running fmt");
        let sh = xshell::Shell::new()?;
        let rust_toolchain = self
            .toolchain
            .or_else(|| sh.var("RUST_TOOLCHAIN").ok())
            .map(|s| format!("+{s}"));

        if rust_toolchain.is_some() {
            log::trace!(
                "fmt toolchain override: fmt --toolchain={}",
                &rust_toolchain.as_ref().unwrap()[1..]
            );
        }

        let fmt_check = (!self.fix).then_some("--check");

        cmd!(sh, "cargo {rust_toolchain...} fmt -- {fmt_check...}")
            .quiet()
            .run()?;

        log::trace!("done fmt");
        Ok(())
    }
}
