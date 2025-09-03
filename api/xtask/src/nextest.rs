// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run nextest

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run nextest
#[derive(Parser)]
#[clap(about = "Run nextest")]
pub struct Nextest {
    /// Features to include in nextest run
    #[clap(long)]
    pub features: Option<String>,

    /// Package argument to run nextest command with
    #[clap(long)]
    pub package: Option<String>,

    /// Whether to include --no-default-features
    #[clap(long)]
    pub no_default_features: bool,
}

impl Xtask for Nextest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running nextest");

        let sh = Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        #[cfg(target_os = "windows")]
        let crypto = String::from("use-symcrypt");
        #[cfg(not(target_os = "windows"))]
        let crypto = String::from("use-openssl");

        // convert xtask parameters into cargo command arguments
        let mut command_args = Vec::new();
        command_args.push("--features");
        let features = format!(
            "{}{}{}",
            crypto,
            if self.features.is_some() { "," } else { "" },
            self.features.unwrap_or("".to_string())
        );
        command_args.push(features.as_str());
        if self.package.is_some() {
            command_args.push("--package");
        }
        let package_val = self.package.clone().unwrap_or("".to_string());
        if self.package.is_some() {
            command_args.push(&package_val);
        }
        if self.no_default_features {
            command_args.push("--no-default-features");
        }

        cmd!(
            sh,
            "cargo {rust_toolchain...} nextest run {command_args...}"
        )
        .quiet()
        .run()?;

        log::trace!("done nextest");
        Ok(())
    }
}
