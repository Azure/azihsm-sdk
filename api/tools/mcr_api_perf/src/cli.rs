// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct CliArgs {
    /// CLI Command
    #[command(subcommand)]
    pub(crate) command: CliCommand,
}

#[derive(Subcommand)]
pub(crate) enum CliCommand {
    /// Performance Test
    Perf(PerfArgs),
}

#[derive(Args)]
pub(crate) struct PerfArgs {
    /// Selected device index
    #[arg(long, default_value_t = 0)]
    pub(crate) device: usize,

    /// Number of test threads
    #[arg(long, default_value_t = 128)]
    pub(crate) threads: usize,

    /// Stabilization time in seconds
    #[arg(long, default_value_t = 5)]
    pub(crate) stabilize_seconds: u64,

    /// Number of seconds to run performance test
    #[arg(long, default_value_t = 100)]
    pub(crate) test_seconds: u64,

    /// Use shared session for all threads or let each thread have their own session
    #[arg(long, default_value_t = false)]
    pub(crate) shared_session: bool,

    /// Hide progress bar
    #[arg(long, default_value_t = false)]
    pub(crate) hide_progress: bool,

    /// Per request time queue size per thread
    #[arg(long, default_value_t = 10000)]
    pub(crate) prt_queue_length: usize,

    /// Mix for testing
    #[command(subcommand)]
    pub(crate) mix: PerfMix,
}

#[derive(Subcommand)]
pub(crate) enum PerfMix {
    /// Custom Performance Mix
    Custom(CustomMixArgs),
}

#[derive(Args)]
pub(crate) struct CustomMixArgs {
    /// Ratio of RSA 2K Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_2k: u16,

    /// Ratio of RSA 3K Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_3k: u16,

    /// Ratio of RSA 4K Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_4k: u16,

    /// Ratio of RSA 2K CRT Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_crt_2k: u16,

    /// Ratio of RSA 3K CRT Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_crt_3k: u16,

    /// Ratio of RSA 4K CRT Sign operations
    #[arg(long, default_value_t = 0)]
    pub(crate) rsa_sign_crt_4k: u16,
}
