// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Firmware build command.

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::fw_util::FwPaths;
use crate::Xtask;
use crate::XtaskCtx;

/// Build firmware.
#[derive(Parser)]
#[clap(about = "Build firmware")]
pub struct Build {
    /// Features to include in the firmware build.
    #[clap(long)]
    pub features: Option<String>,

    /// Build without the crate's default features.
    #[clap(long)]
    pub no_default_features: bool,
}

impl Xtask for Build {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        let sh = Shell::new()?;
        let fw = FwPaths::new(&ctx)?;
        let _dir = sh.push_dir(&fw.fw_dir);

        let mut args = vec!["+nightly", "build", "--release"];
        if self.no_default_features {
            args.push("--no-default-features");
        }
        if let Some(features) = self
            .features
            .as_ref()
            .filter(|features| !features.trim().is_empty())
        {
            args.push("--features");
            args.push(features);
        }

        log::info!("Building firmware...");
        cmd!(sh, "cargo {args...}").run()?;
        log::info!("Firmware build complete.");
        Ok(())
    }
}
