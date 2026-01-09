// Copyright (C) Microsoft Corporation. All rights reserved.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;

use crate::install;
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

    #[clap(long)]
    pub symcrypt_ubuntu_version: Option<String>,

    #[clap(long)]
    pub symcrypt_install_method: Option<String>,

    #[clap(long)]
    pub symcrypt_version: Option<String>,

    #[clap(long)]
    pub symcrypt_os: Option<String>,

    #[clap(long)]
    pub symcrypt_architecture: Option<String>,
}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        #[cfg(target_os = "windows")]
        {
            // Run Install SymCrypt
            let install_symcrypt = install_symcrypt::InstallSymcrypt {
                ubuntu_version: self.symcrypt_ubuntu_version,
                install_method: self.symcrypt_install_method,
                symcrypt_version: self.symcrypt_version,
                os: self.symcrypt_os,
                architecture: self.symcrypt_architecture,
            };
            install_symcrypt.run(ctx.clone())?;
        }

        // Run Install Cargo nextest
        let install_cargo_nextest = install::Install {
            crate_name: "cargo-nextest@0.9.108".to_string(),
            force: self.force,
            config: self.config.clone(),
        };
        install_cargo_nextest.run(ctx.clone())?;

        // Run Install Cargo taplo-cli
        let install_cargo_taplo_cli = install::Install {
            crate_name: "taplo-cli@0.10.0".to_string(),
            force: self.force,
            config: self.config.clone(),
        };
        install_cargo_taplo_cli.run(ctx.clone())?;

        #[cfg(not(target_os = "windows"))]
        {
            // Cargo fuzz
            let install_cargo_fuzz = install::Install {
                crate_name: "cargo-fuzz@0.13.1".to_string(),
                force: self.force,
                config: self.config.clone(),
            };
            install_cargo_fuzz.run(ctx.clone())?;
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
