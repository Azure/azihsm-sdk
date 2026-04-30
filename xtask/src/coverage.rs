// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run code coverage

use clap::Parser;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run code coverage
#[derive(Parser)]
#[clap(about = "Run code coverage using cargo llvm-cov")]
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
}

impl Xtask for Coverage {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
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

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --no-fail-fast {command_args...}"
        )
        .run()?;

        // Check for/create reports directory
        let reports_dir = ctx.root.join("target").join("reports");
        if !reports_dir.exists() {
            log::info!("Creating reports directory at {}", reports_dir.display());
            std::fs::create_dir_all(&reports_dir)?;
        }

        // Find path to azihsm_api_native object file
        let build_dir = ctx
            .root
            .join("target")
            .join("llvm-cov-target")
            .join("debug")
            .join("build");
        let mut native_obj_path = None;
        if build_dir.exists() {
            for entry in std::fs::read_dir(&build_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir()
                    && path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.starts_with("azihsm_api_tests-"))
                        .unwrap_or(false)
                {
                    // check if directory contains 'out' subdirectory to see if it's the cmake build directory
                    if path.join("out").is_dir() {
                        log::info!("Found cmake build directory at: {}", path.display());
                        #[cfg(target_os = "windows")]
                        {
                            native_obj_path =
                                Some(path.join("out").join("build").join("azihsm_api_native.dll"));
                        }
                        #[cfg(not(target_os = "windows"))]
                        {
                            native_obj_path = Some(
                                path.join("out")
                                    .join("build")
                                    .join("libazihsm_api_native.so"),
                            );
                        }
                        break;
                    }
                }
            }
        } else {
            log::warn!(
                "Cargo build-script directory not found at expected path: {}. Coverage reports may be incomplete.",
                build_dir.display()
            );
        }

        // set LLVM_COV_FLAGS to include azihsm_api_native object file in coverage reports
        if let Some(native_obj_path) = native_obj_path {
            if native_obj_path.is_file() {
                let path_str = native_obj_path.to_string_lossy();
                let new_flags = match std::env::var("LLVM_COV_FLAGS") {
                    Ok(existing) if !existing.trim().is_empty() => {
                        format!("{existing} -object {path_str}")
                    }
                    _ => format!("-object {path_str}"),
                };
                sh.set_var("LLVM_COV_FLAGS", new_flags);
            } else {
                log::warn!("Could not find azihsm_api_native object at expected path: {}. Coverage reports may be incomplete.", native_obj_path.display());
            }
        } else {
            log::warn!("Could not find cmake build directory or azihsm_api_native object. Coverage reports may be incomplete.");
        }

        // Generate cobertura report
        log::info!("Generating cobertura report");
        cmd!(
            sh,
            "cargo llvm-cov report --cobertura --output-path ./target/reports/cobertura_sdk.xml --ignore-filename-regex xtask*"
        ).run()?;

        // Generate json report
        log::info!("Generating json report");
        cmd!(
            sh,
            "cargo llvm-cov report --json --summary-only --output-path ./target/reports/sdk-cov.json --ignore-filename-regex xtask*"
        ).run()?;

        // Generate HTML report
        log::info!("Generating HTML report");
        cmd!(sh, " cargo llvm-cov report --html --output-dir ./target/reports/sdk-cov/ --ignore-filename-regex xtask*").run()?;

        log::info!("Code coverage completed successfully");
        Ok(())
    }
}
