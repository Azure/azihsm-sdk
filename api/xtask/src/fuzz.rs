// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run fuzz

use std::path::PathBuf;

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run fuzz
#[derive(Parser)]
#[clap(about = "Run fuzz")]
pub struct Fuzz {}

impl Xtask for Fuzz {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running fuzz");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let mut target_dir = PathBuf::new();
        target_dir.push(".");
        target_dir.push("target");
        target_dir.push("xtask");
        target_dir.push("debug");

        // gather fuzz targets
        let fuzz_targets_bytes = cmd!(sh, "cargo {rust_toolchain...} fuzz list")
            .output()
            .unwrap()
            .stdout;

        let fuzz_targets_string = String::from_utf8_lossy(&fuzz_targets_bytes);

        for target in fuzz_targets_string.lines() {
            let mut target_path = target_dir.clone();
            target_path.push(target);

            cmd!(sh, "{target_path} -runs=128").quiet().run()?;
        }

        log::trace!("done fuzz");
        Ok(())
    }
}
