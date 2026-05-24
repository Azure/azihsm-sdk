// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;
use xshell::cmd;

use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run build
#[derive(Parser)]
#[clap(about = "Run build")]
pub struct Build {
    /// Whether to include --tests argument
    #[clap(long)]
    pub tests: bool,

    /// Whether to include --all-targets argument
    #[clap(long)]
    pub all_targets: bool,

    /// Whether to include --release argument
    #[clap(long)]
    pub release: bool,

    /// Features to include in build
    #[clap(long)]
    pub features: Option<String>,

    /// Package to build
    #[clap(long)]
    pub package: Option<String>,

    /// Target triple to build for (e.g., aarch64-pc-windows-msvc)
    #[clap(long, value_name = "TRIPLE")]
    pub target: Option<String>,
}

impl Xtask for Build {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running build");

        let sh = xshell::Shell::new()?;
        let rust_toolchain = sh.var("RUST_TOOLCHAIN").map(|s| format!("+{s}")).ok();
        let target_dir = common::target_dir()?;

        // Convert xtask parameters into cargo command arguments
        let mut command_args: Vec<&str> = Vec::new();
        if self.tests {
            command_args.push("--tests");
        }
        if self.all_targets {
            command_args.push("--all-targets");
        }
        if self.release {
            command_args.push("--release");
        }

        // Only pass --features when non-empty
        if let Some(feats) = self.features.as_ref().filter(|s| !s.trim().is_empty()) {
            command_args.push("--features");
            command_args.push(feats);
        }

        // Only pass --package when provided
        if let Some(pkg) = self.package.as_ref().filter(|s| !s.trim().is_empty()) {
            command_args.push("--package");
            command_args.push(pkg);
        }

        // Always pass target-dir
        command_args.push("--target-dir");
        let td = target_dir.to_str().expect("target_dir to str");
        command_args.push(td);

        // Pass --target when provided
        if let Some(triple) = self.target.as_ref().filter(|s| !s.trim().is_empty()) {
            command_args.push("--target");
            command_args.push(triple);
        }

        // Elevate warnings to errors, but do not clobber existing RUSTFLAGS (e.g., custom linker)
        let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
        let new_rf = if existing.trim().is_empty() {
            "-D warnings".to_string()
        } else {
            format!("{existing} -D warnings")
        };
        std::env::set_var("RUSTFLAGS", new_rf);

        cmd!(sh, "cargo {rust_toolchain...} build {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done build");
        Ok(())
    }
}
