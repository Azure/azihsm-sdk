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

    /// Whether to exclude OS-specific cryptographic library in features (use-symcrypt on Windows, use-openssl on Linux)
    #[clap(long)]
    pub exclude_os_crypto: bool,
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
        let mut features_vec = Vec::new();
        if !self.exclude_os_crypto {
            features_vec.push(crypto);
        }
        if self.features.is_some() {
            features_vec.push(self.features.unwrap_or("".to_string()));
        }
        let features_val;
        if !features_vec.is_empty() {
            command_args.push("--features");
            features_val = features_vec.join(",");
            command_args.push(&features_val);
        }
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
