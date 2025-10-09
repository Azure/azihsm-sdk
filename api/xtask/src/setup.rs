// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::install;
#[cfg(target_os = "windows")]
use crate::install_symcrypt;
use crate::rustup_component_add;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run various repo-specific checks
#[derive(Parser)]
#[clap(about = "Install all dependencies needed for project")]
pub struct Setup {}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        let sh = Shell::new()?;

        #[cfg(target_os = "windows")]
        {
            // Run Install SymCrypt
            let install_symcrypt = install_symcrypt::InstallSymcrypt {
                ubuntu_version: None,
            };
            install_symcrypt.run(ctx.clone())?;
        }

        // Run Install Cargo nextest
        let install_cargo_nextest = install::Install {
            crate_name: "cargo-nextest".to_string(),
        };
        install_cargo_nextest.run(ctx.clone())?;

        // Check if Clippy is installed by running 'cargo clippy --version'
        if cmd!(sh, "cargo clippy --version").quiet().run().is_err() {
            // Add Clippy
            let add_clippy = rustup_component_add::RustupComponentAdd {
                component: "clippy".to_string(),
                toolchain: None,
            };
            add_clippy.run(ctx.clone())?;
        }

        // Check if Fmt is installed by running 'cargo fmt --version'
        if cmd!(sh, "cargo +nightly fmt --version")
            .quiet()
            .run()
            .is_err()
        {
            // Add Fmt
            let add_fmt = rustup_component_add::RustupComponentAdd {
                component: "rustfmt".to_string(),
                toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
            };
            add_fmt.run(ctx.clone())?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Cargo fuzz
            let install_cargo_fuzz = install::Install {
                crate_name: "cargo-fuzz".to_string(),
            };
            install_cargo_fuzz.run(ctx.clone())?;
        }

        log::trace!("done setup");
        Ok(())
    }
}
