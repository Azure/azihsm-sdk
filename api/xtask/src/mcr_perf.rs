// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run mcr_perf

use std::path::PathBuf;

use clap::Parser;
use xshell::cmd;

use crate::build;
use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

const THREADS_DEFAULT: u32 = 128;
const STABILIZE_SECONDS_DEFAULT: u32 = 5;
const TEST_SECONDS_DEFAULT: u32 = 100;

/// Xtask to run mcr_perf
#[derive(Parser)]
#[clap(about = "Run mcr_perf")]
pub struct McrPerf {
    /// Override path for mcr_perf with custom path. It will also skip building the mcr_perf with mock.
    #[clap(long)]
    pub path_override: Option<String>,

    /// Use shared session for all threads or let each thread have their own session
    #[clap(long)]
    pub shared_session: bool,

    /// Number of test threads
    #[clap(long, default_value_t = THREADS_DEFAULT)]
    pub threads: u32,

    /// Stabilization time in seconds
    #[clap(long, default_value_t = STABILIZE_SECONDS_DEFAULT)]
    pub stabilize_seconds: u32,

    /// Number of seconds to run performance test
    #[clap(long, default_value_t = TEST_SECONDS_DEFAULT)]
    pub test_seconds: u32,

    /// Option to provide to custom command
    #[clap(long)]
    pub custom_option: String,
}

impl Xtask for McrPerf {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running mcr_perf");

        if self.path_override.is_none() {
            // Cargo build mock perf if path_override isn't set
            let build_mock_perf = build::Build {
                tests: false,
                all_targets: false,
                release: false,
                features: Some("mock".to_string()),
                package: Some("mcr_perf".to_string()),
            };
            build_mock_perf.run(ctx.clone())?;
        }

        let sh = xshell::Shell::new()?;

        // convert xtask parameters into mcr_perf arguments
        let mut command_args = Vec::new();
        if self.shared_session {
            command_args.push("--shared-session");
        }
        let threads_val = self.threads.to_string();
        if self.threads != THREADS_DEFAULT {
            command_args.push("--threads");
            command_args.push(&threads_val);
        }
        let stabilize_seconds_val = self.stabilize_seconds.to_string();
        if self.stabilize_seconds != STABILIZE_SECONDS_DEFAULT {
            command_args.push("--stabilize-seconds");
            command_args.push(&stabilize_seconds_val);
        }
        let test_seconds_val = self.test_seconds.to_string();
        if self.test_seconds != TEST_SECONDS_DEFAULT {
            command_args.push("--test-seconds");
            command_args.push(&test_seconds_val);
        }
        command_args.push("custom");
        let custom_option_val = format!("--{}", self.custom_option);
        command_args.push(&custom_option_val);
        command_args.push("100");

        let mut mcr_perf_path;
        if self.path_override.is_some() {
            mcr_perf_path = PathBuf::from(self.path_override.unwrap_or_default());
        } else {
            mcr_perf_path = sh.current_dir();
            mcr_perf_path.push(common::target_dir().display().to_string());
            mcr_perf_path.push("debug");
        }
        mcr_perf_path.push("mcr_perf");
        let mcr_perf_path_display = mcr_perf_path.display().to_string();
        cmd!(sh, "{mcr_perf_path_display} perf {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done mcr_perf");
        Ok(())
    }
}
