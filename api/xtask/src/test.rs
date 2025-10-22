// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific clippy checks

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

const TEST_THREADS_DEFAULT: u32 = 1;

/// Xtask to run various repo-specific clippy checks
#[derive(Parser)]
#[clap(about = "Run tests")]
pub struct Test {
    /// Space or comma separated list of features to activate
    #[clap(long)]
    pub features: Option<String>,

    /// Package to run tests for
    #[clap(long)]
    pub package: Option<String>,

    /// Whether to exclude OS-specific cryptographic library in features (use-symcrypt on Windows, use-openssl on Linux)
    #[clap(long)]
    pub exclude_os_crypto: bool,

    /// Number of threads used for running tests in parallel
    #[clap(long, default_value_t = TEST_THREADS_DEFAULT)]
    pub test_threads: u32,
}

impl Xtask for Test {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running test");

        let sh = xshell::Shell::new()?;
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
            features_vec.push(self.features.unwrap_or_default());
        }
        let features_val;
        if !features_vec.is_empty() {
            command_args.push("--features");
            features_val = features_vec.join(",");
            command_args.push(&features_val);
        }
        let package_val = self.package.clone().unwrap_or_default();
        if self.package.is_some() {
            command_args.push("--package");
            command_args.push(&package_val);
        }
        let test_threads_val = self.test_threads.to_string();
        if self.test_threads != 0 {
            command_args.push("--");
            command_args.push("--test-threads");
            command_args.push(&test_threads_val);
        }

        // elevate warnings to errors for test
        std::env::set_var("RUSTFLAGS", "-D warnings");

        cmd!(sh, "cargo {rust_toolchain...} test {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done test");
        Ok(())
    }
}
