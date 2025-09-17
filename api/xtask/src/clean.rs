// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run clean

use std::path::PathBuf;

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run clean
#[derive(Parser)]
#[clap(about = "Run clean")]
pub struct Clean {}

impl Xtask for Clean {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running clean");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let mut target_dir = PathBuf::new();
        target_dir.push("target");
        target_dir.push("xtask");

        // convert xtask parameters into cargo command arguments
        let command_args = vec!["--target-dir", target_dir.to_str().unwrap()];

        cmd!(sh, "cargo {rust_toolchain...} clean {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done clean");
        Ok(())
    }
}
