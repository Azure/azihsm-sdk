// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run fuzz

use clap::Parser;
use xshell::cmd;

use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run fuzz
#[derive(Parser)]
#[clap(about = "Run fuzz")]
pub struct Fuzz {
    /// Name of the fuzz target
    #[clap(long)]
    pub target: Option<String>,

    /// Will limit the number of tries (runs) before it gives up
    #[clap(long, default_value_t = 128)]
    pub runs: u32,
}

impl Xtask for Fuzz {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running fuzz");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let mut target_dir = common::target_dir();
        target_dir.push("debug");
        let runs = self.runs.to_string();

        if self.target.is_some() {
            let target_val = self.target.unwrap_or_default();
            cmd!(
                sh,
                "cargo {rust_toolchain...} fuzz run {target_val} -runs={runs}"
            )
            .quiet()
            .run()?;
        } else {
            // gather fuzz targets
            let fuzz_targets_bytes = cmd!(sh, "cargo {rust_toolchain...} fuzz list")
                .output()
                .unwrap()
                .stdout;

            let fuzz_targets_string = String::from_utf8_lossy(&fuzz_targets_bytes);

            for target in fuzz_targets_string.lines() {
                let mut target_path = target_dir.clone();
                target_path.push(target);

                cmd!(sh, "{target_path} -runs={runs}").quiet().run()?;
            }
        }

        log::trace!("done fuzz");
        Ok(())
    }
}
