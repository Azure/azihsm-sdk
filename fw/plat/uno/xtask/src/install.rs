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

        let crate_name = self.crate_name;
        let mut command_args = vec!["--locked".to_string()];
        if self.force {
            command_args.push("--force".to_string());
        }
        if self.no_default_features {
            command_args.push("--no-default-features".to_string());
        }
        if let Some(features) = self.features {
            command_args.push("--features".to_string());
            command_args.push(features.join(","));
        }
        if let Some(config) = self.config {
            command_args.push("--config".to_string());
            command_args.push(config);
        }

        let retry_toolchain = rust_toolchain.clone();
        let retry_args = command_args.clone();

        let output = cmd!(
            sh,
            "cargo {rust_toolchain...} install {crate_name} {command_args...}"
        )
        .quiet()
        .ignore_status()
        .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !self.force && stderr.contains("already exists in destination") {
                log::warn!("{crate_name}: a different version is already installed — reinstalling");
                let force = "--force";
                cmd!(
                    sh,
                    "cargo {retry_toolchain...} install {crate_name} {retry_args...} {force}"
                )
                .quiet()
                .run()?;
            } else {
                anyhow::bail!(
                    "command exited with non-zero code `cargo install {crate_name}`: {}\n{}",
                    output.status,
                    stderr.trim()
                );
            }
        }

        log::trace!("done install");
        Ok(())
    }
}
