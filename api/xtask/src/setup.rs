// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

use crate::install_cargo_nextest;
use crate::install_clippy;
use crate::install_fmt;
use crate::install_symcrypt;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Install all dependencies needed for project")]
pub struct Setup {}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        // Run Install SymCrypt
        let install_symcrypt = install_symcrypt::InstallSymcrypt {};
        install_symcrypt.run(ctx.clone())?;

        // Run Install Cargo nextest
        let install_cargo_nextest = install_cargo_nextest::InstallCargoNextest {};
        install_cargo_nextest.run(ctx.clone())?;

        // Run Install Clippy
        let install_clippy = install_clippy::InstallClippy {};
        install_clippy.run(ctx.clone())?;

        // Run Install Fmt
        let install_fmt = install_fmt::InstallFmt {
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        install_fmt.run(ctx.clone())?;

        log::trace!("done setup");
        Ok(())
    }
}
