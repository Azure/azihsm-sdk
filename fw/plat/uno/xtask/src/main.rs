// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(clippy::unwrap_used)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Uno firmware workspace automation.

use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

mod audit;
mod bloat;
mod build;
mod clean;
mod clippy;
mod copyright;
mod filt;
mod fmt;
mod fw_util;
mod install;
mod nm;
mod objdump;
mod precheck;
mod readelf;
mod reggen;
mod rustup_component_add;
mod setup;
mod size;

/// Common context passed into every xtask.
#[derive(Clone)]
pub struct XtaskCtx {
    /// Firmware workspace root directory.
    pub root: PathBuf,
}

/// Common trait implemented by all xtask subcommands.
pub trait Xtask: Parser {
    /// Run the xtask.
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()>;
}

#[derive(Parser)]
#[clap(name = "xtask", about = "Uno firmware workspace automation")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Build(build::Build),
    Clippy(clippy::Clippy),
    Fmt(fmt::Fmt),
    Copyright(copyright::Copyright),
    Precheck(precheck::Precheck),
    Clean(clean::Clean),
    Size(size::Size),
    Bloat(bloat::Bloat),
    Nm(nm::Nm),
    Objdump(objdump::Objdump),
    Readelf(readelf::Readelf),
    Reggen(reggen::Reggen),
    Filt(filt::Filt),
    Audit(audit::Audit),
    Setup(setup::Setup),
}

fn main() {
    env_logger::init();

    if let Err(e) = try_main() {
        log::error!("Error: {:#}", e);
        std::process::exit(1);
    }
}

fn try_main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf();

    std::env::set_current_dir(&root)?;
    let ctx = XtaskCtx { root };

    match cli.command {
        Commands::Build(task) => task.run(ctx),
        Commands::Clippy(task) => task.run(ctx),
        Commands::Fmt(task) => task.run(ctx),
        Commands::Copyright(task) => task.run(ctx),
        Commands::Precheck(task) => task.run(ctx),
        Commands::Clean(task) => task.run(ctx),
        Commands::Size(task) => task.run(ctx),
        Commands::Bloat(task) => task.run(ctx),
        Commands::Nm(task) => task.run(ctx),
        Commands::Objdump(task) => task.run(ctx),
        Commands::Readelf(task) => task.run(ctx),
        Commands::Reggen(task) => task.run(ctx),
        Commands::Filt(task) => task.run(ctx),
        Commands::Audit(task) => task.run(ctx),
        Commands::Setup(task) => task.run(ctx),
    }
}
