// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Xtask to run various repo-specific checks

use clap::Parser;
use xshell::cmd;
use xshell::Shell;

use crate::install;
use crate::rustup_component_add;
use crate::Xtask;
use crate::XtaskCtx;

/// Version constants for installed dependencies
const CARGO_NEXTEST_VERSION: &str = "0.9.132";
const TAPLO_CLI_VERSION: &str = "0.10.0";
#[cfg(not(target_os = "windows"))]
const CARGO_FUZZ_VERSION: &str = "0.13.1";
#[cfg(not(target_os = "windows"))]
const CARGO_CBINDGEN_VERSION: &str = "0.29.2";
const CARGO_AUDIT_VERSION: &str = "0.22.0";
const CARGO_LLVM_COV_VERSION: &str = "0.6.23";

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

    /// Skip installing taplo-cli (TOML formatter)
    #[clap(long)]
    pub skip_taplo: bool,

    /// Skip installing cargo-audit
    #[clap(long)]
    pub skip_audit: bool,

    /// Skip installing OpenSSL
    #[clap(long)]
    pub skip_openssl: bool,

    /// OpenSSL version to install (e.g., "3.0.3", "3.5.0").
    /// Selects the ABI target tree (target/ossl-abi-<major>-<minor>/) where
    /// OpenSSL gets installed under `openssl/`.  When `OPENSSL_DIR` is set or
    /// `--skip-openssl` is given, the install step is skipped but the flag
    /// still routes any later cargo invocation in this process to the
    /// matching ABI tree.
    #[clap(long, default_value = "3.0.3")]
    pub openssl_version: String,
}

impl Xtask for Setup {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("running setup");

        let sh = Shell::new()?;

        // Run Install Cargo nextest
        let install_cargo_nextest = install::Install {
            crate_name: format!("cargo-nextest@{}", CARGO_NEXTEST_VERSION),
            force: self.force,
            config: self.config.clone(),
            no_default_features: true,
            features: Some(vec!["default-no-update".to_string()]),
        };
        install_cargo_nextest.run(ctx.clone())?;

        // Check nextest version
        cmd!(sh, "cargo nextest --version").quiet().run()?;

        // Run Install Cargo taplo-cli
        if !self.skip_taplo {
            let install_cargo_taplo_cli = install::Install {
                crate_name: format!("taplo-cli@{}", TAPLO_CLI_VERSION),
                force: self.force,
                config: self.config.clone(),
                no_default_features: false,
                features: None,
            };
            install_cargo_taplo_cli.run(ctx.clone())?;

            // Check taplo-cli version
            cmd!(sh, "taplo --version").quiet().run()?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Cargo fuzz
            let install_cargo_fuzz = install::Install {
                crate_name: format!("cargo-fuzz@{}", CARGO_FUZZ_VERSION),
                force: self.force,
                config: self.config.clone(),
                no_default_features: false,
                features: None,
            };
            install_cargo_fuzz.run(ctx.clone())?;

            // Check cargo-fuzz version
            cmd!(sh, "cargo fuzz --version").quiet().run()?;
        }

        #[cfg(not(target_os = "windows"))]
        {
            // Run install cbindgen
            let install_cbindgen = install::Install {
                crate_name: format!("cbindgen@{}", CARGO_CBINDGEN_VERSION),
                force: self.force,
                config: self.config.clone(),
                no_default_features: false,
                features: None,
            };
            install_cbindgen.run(ctx.clone())?;

            // Check cbindgen version
            cmd!(sh, "cbindgen --version").quiet().run()?;
        }

        // Run Install cargo-audit
        if !self.skip_audit {
            let install_cargo_audit = install::Install {
                crate_name: format!("cargo-audit@{}", CARGO_AUDIT_VERSION),
                force: self.force,
                config: self.config.clone(),
                no_default_features: false,
                features: None,
            };
            install_cargo_audit.run(ctx.clone())?;

            // Check cargo-audit version
            cmd!(sh, "cargo audit --version").quiet().run()?;
        }

        // Run Install cargo-llvm-cov
        let install_cargo_llvm_cov = install::Install {
            crate_name: format!("cargo-llvm-cov@{}", CARGO_LLVM_COV_VERSION),
            force: self.force,
            config: self.config.clone(),
            no_default_features: false,
            features: None,
        };
        install_cargo_llvm_cov.run(ctx.clone())?;

        // Check cargo-llvm-cov version
        cmd!(sh, "cargo llvm-cov --version").quiet().run()?;

        // Add Clippy
        let add_clippy = rustup_component_add::RustupComponentAdd {
            component: "clippy".to_string(),
            toolchain: None,
        };
        // ignore failure in adding Clippy
        if add_clippy.run(ctx.clone()).is_ok() {
            // Check Clippy version
            let _ = cmd!(sh, "cargo clippy --version").quiet().run();
        }

        // Add Fmt
        let add_fmt = rustup_component_add::RustupComponentAdd {
            component: "rustfmt".to_string(),
            toolchain: Some("nightly".to_string()), // Use nightly toolchain by default
        };
        // ignore failure in adding Fmt
        if add_fmt.run(ctx.clone()).is_ok() {
            // Check Fmt version
            let _ = cmd!(sh, "cargo +nightly fmt --version").quiet().run();
        }

        // Route any later cargo invocation in this process to the ABI tree
        // for the requested OpenSSL version, regardless of whether we install
        // OpenSSL ourselves.  The install step itself is gated on
        // `--skip-openssl` (and skipped when OPENSSL_DIR is already set).
        #[cfg(target_os = "linux")]
        {
            let abi_leaf = crate::openssl_install::abi_leaf_for(&self.openssl_version)?;
            let target_dir = ctx.root.join("target").join(&abi_leaf);
            std::env::set_var("CARGO_TARGET_DIR", &target_dir);
            log::info!("CARGO_TARGET_DIR set to {}", target_dir.display());

            if !self.skip_openssl {
                crate::openssl_install::ensure_openssl_version(&self.openssl_version)?;
            }
        }

        log::trace!("done setup");
        Ok(())
    }
}
