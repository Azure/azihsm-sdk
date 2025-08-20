// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific clippy checks

use std::env;
use std::path::PathBuf;

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific clippy checks
#[derive(Parser)]
#[clap(about = "Run build")]
pub struct Build {}

impl Xtask for Build {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running build");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let crypto = if env::consts::OS == "windows" {
            String::from("use-symcrypt")
        } else {
            String::from("use-openssl")
        };
        let mut target_dir = PathBuf::new();
        target_dir.push("target");
        target_dir.push("xtask");

        cmd!(
            sh,
            "cargo {rust_toolchain...} build --features {crypto} --target-dir {target_dir}"
        )
        .quiet()
        .run()?;

        log::trace!("done build");
        Ok(())
    }
}
