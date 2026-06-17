// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to clean & run code coverage

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to clean & run code coverage
#[derive(Parser)]
#[clap(about = "Clean & run code coverage using cargo llvm-cov")]
pub struct Coverage {
    /// Features to include in nextest run
    #[clap(long)]
    pub features: Option<String>,

    /// Package argument to run nextest command with
    #[clap(long)]
    pub package: Option<String>,

    /// Whether to include --no-default-features
    #[clap(long)]
    pub no_default_features: bool,

    /// Test filterset (see https://nexte.st/docs/filtersets)
    #[clap(long, short = 'E')]
    pub filterset: Option<String>,

    /// The nextest profile to use
    #[clap(long)]
    pub profile: Option<String>,

    /// Crates to exclude from nextest (e.g. crates with heavyweight build scripts)
    #[clap(long)]
    pub exclude: Vec<String>,

    /// Skip cleaning existing llvm-cov artifacts before running coverage
    #[clap(long)]
    pub skip_clean: bool,
}

impl Xtask for Coverage {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running code coverage");

        let sh = xshell::Shell::new()?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // convert xtask parameters into cargo command arguments
        let mut command_args = Vec::new();
        let mut features_vec = Vec::new();
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
        if self.no_default_features {
            command_args.push("--no-default-features");
        }
        let filterset_val = self.filterset.clone().unwrap_or_default();
        if self.filterset.is_some() {
            command_args.push("--filterset");
            command_args.push(&filterset_val);
        }
        let profile_val = self.profile.clone().unwrap_or_default();
        if self.profile.is_some() {
            command_args.push("--profile");
            command_args.push(&profile_val);
        }
        let exclude_vals: Vec<String>;
        if self.package.is_none() {
            command_args.push("--workspace");
            if !self.exclude.is_empty() {
                exclude_vals = self
                    .exclude
                    .iter()
                    .flat_map(|c| ["--exclude".to_string(), c.clone()])
                    .collect();
                for val in &exclude_vals {
                    command_args.push(val);
                }
            }
        }

        // Clean existing llvm-cov artifacts unless --skip-clean is set
        if !self.skip_clean {
            log::info!("Cleaning existing llvm-cov artifacts");
            cmd!(sh, "cargo llvm-cov clean --workspace").run()?;
        } else {
            log::info!("Skipping llvm-cov cleanup");
        }

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --no-fail-fast {command_args...}"
        )
        .run()?;

        log::info!("Code coverage completed successfully");
        Ok(())
    }
}

impl From<crate::nextest::Nextest> for Coverage {
    fn from(nextest: crate::nextest::Nextest) -> Self {
        Self {
            features: nextest.features,
            package: nextest.package,
            no_default_features: nextest.no_default_features,
            filterset: nextest.filterset,
            profile: nextest.profile,
            exclude: nextest.exclude,
            skip_clean: false,
        }
    }
}
