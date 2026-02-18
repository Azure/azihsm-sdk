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
}

impl Xtask for Install {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running install");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();

        // convert xtask parameters into cargo command arguments
        let mut command_args = Vec::new();
        command_args.push(self.crate_name.as_str());
        command_args.push("--locked");
        if self.force {
            command_args.push("--force");
        }
        let config_val;
        if self.config.is_some() {
            command_args.push("--config");
            config_val = self.config.unwrap_or_default();
            command_args.push(&config_val);
        }

        cmd!(sh, "cargo {rust_toolchain...} install {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done install");
        Ok(())
    }
}
