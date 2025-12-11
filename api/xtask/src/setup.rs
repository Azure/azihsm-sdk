// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

#[cfg(target_os = "windows")]
use crate::install_symcrypt;
use crate::rustup_component_add;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Install all dependencies needed for project")]
pub struct Setup {
    /// Force overwriting existing crates or binaries
    #[clap(long)]
    pub force: bool,

    /// Override a configuration value in install::Install subtasks
    #[clap(long)]
    pub config: Option<String>,
}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        #[cfg(target_os = "windows")]
        {
            // Run Install SymCrypt
            let install_symcrypt = install_symcrypt::InstallSymcrypt {
                ubuntu_version: None,
            };
            install_symcrypt.run(ctx.clone())?;
        }

        // Add Clippy
        let add_clippy = rustup_component_add::RustupComponentAdd {
            component: "clippy".to_string(),
            toolchain: None,
        };
        // ignore failure in adding Clippy
        let _ = add_clippy.run(ctx.clone());

        // Add Fmt
        let add_fmt = rustup_component_add::RustupComponentAdd {
            component: "rustfmt".to_string(),
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        // ignore failure in adding Fmt
        let _ = add_fmt.run(ctx.clone());

        log::trace!("done setup");
        Ok(())
    }
}
