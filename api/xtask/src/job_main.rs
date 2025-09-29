// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run job: Main

use clap::Parser;

use crate::build;
use crate::clean;
use crate::clippy;
use crate::fmt;
#[cfg(not(target_os = "windows"))]
use crate::fuzz;
use crate::mcr_perf;
use crate::nextest;
use crate::setup;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run job: Main
#[derive(Parser)]
#[clap(about = "Run job: Main")]
pub struct JobMain {}

impl Xtask for JobMain {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running job: Main");

        // Run Setup
        let setup = setup::Setup {};
        setup.run(ctx.clone())?;

        // Run Clippy
        let clippy = clippy::Clippy {};
        clippy.run(ctx.clone())?;

        // Run Fmt
        let fmt = fmt::Fmt {
            fix: false,                             // Do not fix formatting issues by default
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        fmt.run(ctx.clone())?;

        // elevate warnings to errors for all build steps
        std::env::set_var("RUSTFLAGS", "-D warnings");

        // Build mcr_ddi tests
        let mut cwd = ctx.root.clone();
        cwd.extend(["ddi", "lib", "tests"]);
        std::env::set_current_dir(cwd.as_path())?;
        let clean_mcr_ddi_tests = clean::Clean {};
        clean_mcr_ddi_tests.run(ctx.clone())?;
        let build_mcr_ddi_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: None,
            package: None,
        };
        build_mcr_ddi_tests.run(ctx.clone())?;

        // Build mcr_api tests
        cwd = ctx.root.clone();
        cwd.extend(["lib", "tests"]);
        std::env::set_current_dir(cwd.as_path())?;
        let clean_mcr_api_tests = clean::Clean {};
        clean_mcr_api_tests.run(ctx.clone())?;
        let build_mcr_api_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: None,
            package: None,
        };
        build_mcr_api_tests.run(ctx.clone())?;

        // Build mcr_api_hook tests
        let clean_mcr_api_hook_tests = clean::Clean {};
        clean_mcr_api_hook_tests.run(ctx.clone())?;
        let build_mcr_api_hook_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: Some("testhooks".to_string()),
            package: None,
        };
        build_mcr_api_hook_tests.run(ctx.clone())?;

        // Cargo build release
        cwd = ctx.root.clone();
        std::env::set_current_dir(cwd.as_path())?;
        let build_release = build::Build {
            tests: false,
            all_targets: true,
            release: true,
            features: None,
            package: None,
        };
        build_release.run(ctx.clone())?;

        // Cargo test mock 1 table
        let test_mock_1_table = nextest::Nextest {
            features: Some("mock,testhooks".to_string()),
            package: None,
            no_default_features: false,
        };
        test_mock_1_table.run(ctx.clone())?;

        // Cargo test crypto package with OpenSSL
        let test_crypto_package = nextest::Nextest {
            features: None,
            package: Some("crypto".to_string()),
            no_default_features: false,
        };
        test_crypto_package.run(ctx.clone())?;

        let test_mcr_api_package = nextest::Nextest {
            features: Some("mock".to_string()),
            package: Some("mcr_api".to_string()),
            no_default_features: true,
        };
        test_mcr_api_package.run(ctx.clone())?;

        #[cfg(not(target_os = "windows"))]
        {
            let build_mock_testhooks = build::Build {
                tests: false,
                all_targets: false,
                release: false,
                features: Some("mock,testhooks".to_string()),
                package: None,
            };
            build_mock_testhooks.run(ctx.clone())?;

            let cargo_fuzz = fuzz::Fuzz {
                target: None,
                runs: 128,
            };
            cargo_fuzz.run(ctx.clone())?;

            // Cargo test mock 4 tables
            let test_mock_4_table = nextest::Nextest {
                features: Some("mock,testhooks,table-4".to_string()),
                package: None,
                no_default_features: false,
            };
            test_mock_4_table.run(ctx.clone())?;

            // Cargo test mock 64 tables
            let test_mock_64_table = nextest::Nextest {
                features: Some("mock,testhooks,table-64".to_string()),
                package: None,
                no_default_features: false,
            };
            test_mock_64_table.run(ctx.clone())?;
        }

        // Cargo build mock perf
        let build_mock_perf = build::Build {
            tests: false,
            all_targets: false,
            release: false,
            features: Some("mock".to_string()),
            package: Some("mcr_perf".to_string()),
        };
        build_mock_perf.run(ctx.clone())?;

        // Mock Perf test - multi-threaded
        cwd = ctx.root.clone();
        cwd.extend(["target", "xtask", "debug"]);
        std::env::set_current_dir(cwd.as_path())?;
        let mock_perf_test_get_api_rev = mcr_perf::McrPerf {
            shared_session: true,
            threads: 120,
            stabilize_seconds: 5,
            test_seconds: 10,
            command: mcr_perf::Commands::Custom {
                get_api_rev: 100,
                aes_cbc_128_encrypt: 0,
            },
        };
        mock_perf_test_get_api_rev.run(ctx.clone())?;

        let mock_perf_test_aes_cbc_128_encrypt = mcr_perf::McrPerf {
            shared_session: true,
            threads: 200,
            stabilize_seconds: 5,
            test_seconds: 10,
            command: mcr_perf::Commands::Custom {
                get_api_rev: 0,
                aes_cbc_128_encrypt: 100,
            },
        };
        mock_perf_test_aes_cbc_128_encrypt.run(ctx.clone())?;

        log::trace!("done job: Main");
        Ok(())
    }
}
