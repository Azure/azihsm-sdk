// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run mcr_perf

use clap::Parser;
use clap::Subcommand;
use xshell::cmd;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run mcr_perf
#[derive(Parser)]
#[clap(about = "Run mcr_perf")]
pub struct McrPerf {
    /// Use shared session for all threads or let each thread have their own session
    #[clap(long)]
    pub shared_session: bool,

    /// Number of test threads [default: 128]
    #[clap(long)]
    pub threads: Option<u32>,

    /// Stabilization time in seconds [default: 5]
    #[clap(long)]
    pub stabilize_seconds: Option<u32>,

    /// Number of seconds to run performance test [default: 100]
    #[clap(long)]
    pub test_seconds: Option<u32>,

    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Custom {
        /// Ratio of Get API Revision operations [default: 0]
        #[clap(long)]
        get_api_rev: Option<u32>,

        /// Ratio of AES-CBC 128 Encrypt operations [default: 0]
        #[clap(long)]
        aes_cbc_128_encrypt: Option<u32>,
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
        let threads_val = self.threads.unwrap_or(128).to_string();
        if self.threads.is_some() {
            command_args.push("--threads");
            command_args.push(&threads_val);
        }
        let stabilize_seconds_val = self.stabilize_seconds.unwrap_or(5).to_string();
        if self.stabilize_seconds.is_some() {
            command_args.push("--stabilize-seconds");
            command_args.push(&stabilize_seconds_val);
        }
        let test_seconds_val = self.test_seconds.unwrap_or(100).to_string();
        if self.test_seconds.is_some() {
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
                get_api_rev_val = get_api_rev.unwrap_or(0).to_string();
                if get_api_rev.is_some() {
                    command_args.push("--get-api-rev");
                    command_args.push(&get_api_rev_val);
                }
                aes_cbc_128_encrypt_val = aes_cbc_128_encrypt.unwrap_or(0).to_string();
                if aes_cbc_128_encrypt.is_some() {
                    command_args.push("--aes-cbc-128-encrypt");
                    command_args.push(&aes_cbc_128_encrypt_val);
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            let mut cwd = sh.current_dir();
            cwd.extend(["mcr_perf.exe"]);
            let mcr_perf_path = cwd.display().to_string();
            cmd!(sh, "{mcr_perf_path} perf {command_args...}")
                .quiet()
                .run()?;
        }
        #[cfg(not(target_os = "windows"))]
        cmd!(sh, "./mcr_perf perf {command_args...}")
            .quiet()
            .run()?;

        log::trace!("done mcr_perf");
        Ok(())
    }
}
