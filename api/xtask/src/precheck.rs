// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

use crate::build;
use crate::clean;
use crate::clippy;
use crate::copyright;
use crate::fmt;
#[cfg(not(target_os = "windows"))]
use crate::fuzz;
use crate::mcr_perf;
use crate::nextest;
use crate::setup;
use crate::test;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Run various checks")]
pub struct Precheck {}

impl Xtask for Precheck {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running precheck");

        // Run Setup
        let setup = setup::Setup {
            force: false,
            config: None,
        };
        setup.run(ctx.clone())?;

        // Run Copyright
        let copyright = copyright::Copyright { fix: false };
        copyright.run(ctx.clone())?;

        // Run Clippy
        let clippy = clippy::Clippy {};
        clippy.run(ctx.clone())?;

        // Run Fmt
        let fmt = fmt::Fmt {
            fix: false,                             // Do not fix formatting issues by default
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        fmt.run(ctx.clone())?;

        // Build mcr_ddi tests
        let clean_mcr_ddi_tests = clean::Clean {};
        clean_mcr_ddi_tests.run(ctx.clone())?;
        let build_mcr_ddi_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: None,
            package: Some("mcr_ddi".to_string()),
        };
        build_mcr_ddi_tests.run(ctx.clone())?;

        // Build mcr_api tests
        let clean_mcr_api_tests = clean::Clean {};
        clean_mcr_api_tests.run(ctx.clone())?;
        let build_mcr_api_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: None,
            package: Some("mcr_api".to_string()),
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
            package: Some("mcr_api".to_string()),
        };
        build_mcr_api_hook_tests.run(ctx.clone())?;

        // Cargo build release
        let build_release = build::Build {
            tests: false,
            all_targets: true,
            release: true,
            features: None,
            package: None,
        };
        build_release.run(ctx.clone())?;

        // Cargo test mock
        let test_mock_1_table = nextest::Nextest {
            features: Some("mock,testhooks".to_string()),
            package: None,
            no_default_features: false,
            filterset: Some("not package(mcr_api_resilient)".to_string()),
        };
        test_mock_1_table.run(ctx.clone())?;

        // Cargo test mcr_api_resilient package
        let test_mcr_api_resilient = test::Test {
            features: Some("mock,testhooks".to_string()),
            package: Some("mcr_api_resilient".to_string()),
            exclude_os_crypto: false,
            test_threads: 1,
        };
        test_mcr_api_resilient.run(ctx.clone())?;

        // Cargo test crypto package
        let test_crypto_package = nextest::Nextest {
            features: None,
            package: Some("crypto".to_string()),
            no_default_features: false,
            filterset: None,
        };
        test_crypto_package.run(ctx.clone())?;

        let test_mcr_api_package = nextest::Nextest {
            features: Some("mock".to_string()),
            package: Some("mcr_api".to_string()),
            no_default_features: true,
            filterset: None,
        };
        test_mcr_api_package.run(ctx.clone())?;

        #[cfg(not(target_os = "windows"))]
        {
            // Cargo fuzz
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
                filterset: Some("not package(mcr_api_resilient)".to_string()),
            };
            test_mock_4_table.run(ctx.clone())?;

            // Cargo test mock 64 tables
            let test_mock_64_table = nextest::Nextest {
                features: Some("mock,testhooks,table-64".to_string()),
                package: None,
                no_default_features: false,
                filterset: Some("not package(mcr_api_resilient)".to_string()),
            };
            test_mock_64_table.run(ctx.clone())?;
        }

        // Mock Perf test - multi-threaded
        let mock_perf_test_get_api_rev = mcr_perf::McrPerf {
            path_override: None,
            shared_session: true,
            threads: 120,
            stabilize_seconds: 5,
            test_seconds: 10,
            custom_option: "get-api-rev".to_string(),
        };
        mock_perf_test_get_api_rev.run(ctx.clone())?;

        let mock_perf_test_aes_cbc_128_encrypt = mcr_perf::McrPerf {
            path_override: None,
            shared_session: true,
            threads: 200,
            stabilize_seconds: 5,
            test_seconds: 10,
            custom_option: "aes-cbc-128-encrypt".to_string(),
        };
        mock_perf_test_aes_cbc_128_encrypt.run(ctx.clone())?;

        log::trace!("done precheck");
        Ok(())
    }
}
