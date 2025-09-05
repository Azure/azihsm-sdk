// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run job: Windows

use clap::Parser;

use crate::build;
use crate::clippy;
use crate::fmt;
use crate::mcr_perf;
use crate::nextest;
use crate::setup;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run job: Windows
#[derive(Parser)]
#[clap(about = "Run job: Windows")]
pub struct JobWindows {}

impl Xtask for JobWindows {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running job: Windows");

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

        // Build mcr_ddi tests
        let mut cwd = ctx.root.clone();
        cwd.extend(["ddi", "lib", "tests"]);
        std::env::set_current_dir(cwd.as_path())?;
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
        let build_mcr_api_tests = build::Build {
            tests: true,
            all_targets: false,
            release: false,
            features: None,
            package: None,
        };
        build_mcr_api_tests.run(ctx.clone())?;

        // Build mcr_api_hook tests
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

        // Cargo test crypto package with symcrypt
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
            threads: Some(120),
            stabilize_seconds: Some(5),
            test_seconds: Some(10),
            command: mcr_perf::Commands::Custom {
                get_api_rev: Some(100),
                aes_cbc_128_encrypt: None,
            },
        };
        mock_perf_test_get_api_rev.run(ctx.clone())?;

        let mock_perf_test_aes_cbc_128_encrypt = mcr_perf::McrPerf {
            shared_session: true,
            threads: Some(200),
            stabilize_seconds: Some(5),
            test_seconds: Some(10),
            command: mcr_perf::Commands::Custom {
                get_api_rev: None,
                aes_cbc_128_encrypt: Some(100),
            },
        };
        mock_perf_test_aes_cbc_128_encrypt.run(ctx.clone())?;

        log::trace!("done job: Windows");
        Ok(())
    }
}
