// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run mcr_perf

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;
use xshell::cmd;

use crate::common;
use crate::Xtask;
use crate::XtaskCtx;

const THREADS_DEFAULT: u32 = 128;
const STABILIZE_SECONDS_DEFAULT: u32 = 5;
const TEST_SECONDS_DEFAULT: u32 = 100;
const GET_API_REV_DEFAULT: u32 = 0;
const AES_CBC_128_ENCRYPT_DEFAULT: u32 = 0;

/// Xtask to run mcr_perf
#[derive(Parser)]
#[clap(about = "Run mcr_perf")]
pub struct McrPerf {
    /// override default path (directory of xtask.exe) with custom path
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

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Custom {
        /// Ratio of Get API Revision operations
        #[clap(long, default_value_t = GET_API_REV_DEFAULT)]
        get_api_rev: u32,

        /// Ratio of AES-CBC 128 Encrypt operations
        #[clap(long, default_value_t = AES_CBC_128_ENCRYPT_DEFAULT)]
        aes_cbc_128_encrypt: u32,
    },
}

impl Xtask for McrPerf {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running mcr_perf");

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
        let get_api_rev_val;
        let aes_cbc_128_encrypt_val;
        match self.command {
            Commands::Custom {
                get_api_rev,
                aes_cbc_128_encrypt,
            } => {
                command_args.push("custom");
                get_api_rev_val = get_api_rev.to_string();
                if get_api_rev != GET_API_REV_DEFAULT {
                    command_args.push("--get-api-rev");
                    command_args.push(&get_api_rev_val);
                }
                aes_cbc_128_encrypt_val = aes_cbc_128_encrypt.to_string();
                if aes_cbc_128_encrypt != AES_CBC_128_ENCRYPT_DEFAULT {
                    command_args.push("--aes-cbc-128-encrypt");
                    command_args.push(&aes_cbc_128_encrypt_val);
                }
            }
        }

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
