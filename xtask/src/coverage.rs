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
pub struct Coverage {}

impl Xtask for Coverage {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running code coverage");

        let sh = xshell::Shell::new()?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // Run tests with coverage
        log::info!("Building all tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --no-fail-fast --features mock --profile ci-mock --workspace --exclude provider-integration-tests-cli --exclude provider-integration-tests-capi"
        )
        .run()?;

        // Run resiliency fault-injection tests with coverage
        log::info!("Building resiliency fault-injection tests and running them with coverage");
        cmd!(
            sh,
            "cargo llvm-cov nextest --no-report --no-fail-fast -E test(resiliency::fault_injection::) --features mock,res-test --package azihsm_api_tests --profile ci-mock-res"
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
