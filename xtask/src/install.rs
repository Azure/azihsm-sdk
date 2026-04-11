// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run install

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run install
#[derive(Parser)]
#[clap(about = "Run Install")]
pub struct Install {
    /// Name of crate to install
    #[clap(long)]
    pub crate_name: String,

    /// Force overwriting existing crates or binaries
    #[clap(long)]
    pub force: bool,

    /// Override a configuration value
    #[clap(long)]
    pub config: Option<String>,

    /// Assign "--no-default-features"
    #[clap(long, default_value_t = false)]
    pub no_default_features: bool,

    /// Specify features
    #[clap(long)]
    pub features: Option<Vec<String>>,
}

impl Xtask for Install {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // convert xtask parameters into cargo command arguments
        let mut command_args = vec![self.crate_name, "--locked".to_string()];
        if self.force {
            command_args.push("--force".to_string());
        }

        if self.no_default_features {
            command_args.push("--no-default-features".to_string());
        }

        if let Some(features) = self.features {
            let features = features.join(",");
            command_args.push("--features".to_string());
            command_args.push(features);
        }

        if let Some(config) = self.config {
            command_args.push("--config".to_string());
            command_args.push(config);
        }

        cmd!(sh, "cargo {rust_toolchain...} install {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done install");
        Ok(())
    }
}
