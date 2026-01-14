// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

use crate::clippy;
use crate::copyright;
use crate::fmt;
use crate::nextest;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Run various checks")]
pub struct Precheck {
    /// Skip TOML formatting
    #[clap(long)]
    pub skip_toml: bool,
}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        // Run Copyright
        let copyright = copyright::Copyright { fix: false };
        copyright.run(ctx.clone())?;

        // Run Fmt
        let fmt = fmt::Fmt {
            fix: false,                             // Do not fix formatting issues by default
            skip_toml: self.skip_toml,              // Pass through skip_toml flag
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        fmt.run(ctx.clone())?;

        // Run Clippy
        let clippy = clippy::Clippy {};
        clippy.run(ctx.clone())?;

        // Run Rust tests
        let nextest = nextest::Nextest {
            features: Some("mock".to_string()),
            package: None,
            no_default_features: false,
            filterset: None,
        };
        nextest.run(ctx.clone())?;

        log::trace!("done precheck");
        Ok(())
    }
}
