// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Azihsm repo-specific automation.
//!
//! Follows the xtask workflow/convention, as described at
//! <https://github.com/matklad/cargo-xtask>

use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

mod build;
mod clippy;
pub mod common;
mod copyright;
mod fmt;
mod precheck;
mod test;
mod nextest;

/// Common context passed into every Xtask
#[derive(Clone)]
pub struct XtaskCtx {
    /// Project root directory
    pub root: PathBuf,
}

/// Common trait implemented by all Xtask subcommands.
pub trait Xtask: Parser {
    /// Run the Xtask.
    ///
    /// For consistency and simplicity, `Xtask` implementations are allowed to
    /// assume that they are being run from the root of the repo's filesystem.
    /// Callers of `Xtask::run` should take care to ensure
    /// [`std::env::set_current_dir`] was called prior to invoking `Xtask::run`.
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()>;
}

#[derive(Parser)]
#[clap(name = "xtask", about = "Azihsm repo automation")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Build(build::Build),
    Precheck(precheck::Precheck),
    Clippy(clippy::Clippy),
    Copyright(copyright::Copyright),
    Fmt(fmt::Fmt),
    Test(test::Test),
	Nextest(nextest::Nextest),
}

fn main() {
    env_logger::init();

    if let Err(e) = try_main() {
        log::error!("Error: {:#}", e);
        std::process::exit(-1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let root = Path::new(&env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf();

    // for consistency, always run xtasks as though they were run from the root
    std::env::set_current_dir(&root)?;

    let ctx = XtaskCtx { root };

    match cli.command {
        Commands::Build(task) => task.run(ctx),
        Commands::Clippy(task) => task.run(ctx),
        Commands::Copyright(task) => task.run(ctx),
        Commands::Fmt(task) => task.run(ctx),
        Commands::Precheck(task) => task.run(ctx),
        Commands::Test(task) => task.run(ctx),
		Commands::Nextest(task) => task.run(ctx),
    }
}
