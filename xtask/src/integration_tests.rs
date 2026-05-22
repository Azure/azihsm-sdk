// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests
#[derive(Parser)]
#[clap(about = "Run Integration Tests")]
pub struct IntegrationTest {
    /// OpenSSL version to use (e.g., "3.0.3", "3.5.0").
    /// Selects the ABI target tree (target/ossl-abi-<major>-<minor>/) where
    /// artifacts are built.  When OPENSSL_DIR is set, that location overrides
    /// the install step's path, but the flag still controls the build's
    /// target dir, so artifacts are correctly ABI-isolated.
    #[clap(long, default_value = "3.0.3")]
    pub openssl_version: String,
}

impl Xtask for IntegrationTest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("start testing");

        #[cfg(not(target_os = "linux"))]
        {
            log::warn!("skipping provider integration tests: only supported on Linux");
            Ok(())
        }

        #[cfg(target_os = "linux")]
        {
            // Set CARGO_TARGET_DIR so the provider build (and all artifacts)
            // land in the ABI-versioned tree.  build.rs enforces this convention.
            let abi_leaf = crate::openssl_install::abi_leaf_for(&self.openssl_version)?;
            let target_dir = _ctx.root.join("target").join(&abi_leaf);
            std::env::set_var("CARGO_TARGET_DIR", &target_dir);
            log::info!("CARGO_TARGET_DIR set to {}", target_dir.display());

            let openssl_dir = crate::openssl_install::check_openssl(&self.openssl_version)?;

            // Build the provider and its native FFI dep before running tests.
            // The provider's build.rs isolates CMake/Corrosion's nested cargo
            // into a separate target dir (see corrosion-target in build.rs)
            // so this no longer deadlocks the outer `cargo xtask` invocation.
            let sh = xshell::Shell::new()?;
            xshell::cmd!(sh, "cargo build -p azihsm_api_native --features mock").run()?;
            xshell::cmd!(sh, "cargo build -p azihsm_ossl_provider --features mock").run()?;

            if std::env::var("OPENSSL_BIN").is_err() {
                std::env::set_var("OPENSSL_BIN", openssl_dir.join("bin/openssl"));
            }
            // Probe lib64 first (common on 64-bit distros), then fall back to lib.
            // Also include the cargo debug dir so libazihsm_api_native.so is
            // resolved from Cargo's build (not the parallel one Corrosion
            // creates under target/<abi>/debug/build/.../out/build/, which has
            // a different code path baked in).
            if std::env::var("OPENSSL_LIB").is_err() {
                let lib64 = openssl_dir.join("lib64");
                let lib = openssl_dir.join("lib");
                let cargo_debug = target_dir.join("debug");
                let openssl_lib = if lib64.is_dir() {
                    Some(lib64)
                } else if lib.is_dir() {
                    Some(lib)
                } else {
                    log::warn!(
                        "neither {}/lib64 nor {}/lib exists",
                        openssl_dir.display(),
                        openssl_dir.display()
                    );
                    None
                };
                if let Some(p) = openssl_lib {
                    std::env::set_var(
                        "OPENSSL_LIB",
                        format!("{}:{}", p.display(), cargo_debug.display()),
                    );
                }
            }
            if std::env::var("OPENSSL_DIR").is_err() {
                std::env::set_var("OPENSSL_DIR", &openssl_dir);
            }

            // Test key material is shared across versions (regenerated per run).
            // Keep it at the top of target/, not inside the ABI tree.
            let keymat_dir = _ctx.root.join("target").join("test-keymat");
            if keymat_dir.exists() {
                std::fs::remove_dir_all(&keymat_dir)?;
                log::trace!(
                    "cleaned previous test key material at {}",
                    keymat_dir.display()
                );
            }

            crate::nextest::Nextest {
                features: Some("integration".to_string()),
                package: Some("provider-integration-tests-cli".to_string()),
                no_default_features: false,
                filterset: None,
                profile: Some("ci-provider-integration".to_string()),
                exclude: vec![],
            }
            .run(_ctx.clone())?;

            crate::nextest::Nextest {
                features: Some("integration".to_string()),
                package: Some("provider-integration-tests-capi".to_string()),
                no_default_features: false,
                filterset: None,
                profile: Some("ci-provider-integration".to_string()),
                exclude: vec![],
            }
            .run(_ctx.clone())?;

            crate::nextest::Nextest {
                features: Some("integration".to_string()),
                package: Some("provider-integration-tests-nginx".to_string()),
                no_default_features: false,
                filterset: None,
                profile: Some("ci-provider-integration".to_string()),
                exclude: vec![],
            }
            .run(_ctx)
        }
    }
}
