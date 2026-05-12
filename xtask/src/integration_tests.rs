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
    /// When OPENSSL_DIR is set, this flag is ignored and the
    /// existing installation is used as-is.
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
            let openssl_dir = crate::openssl_install::check_openssl(&self.openssl_version)?;

            if std::env::var("OPENSSL_BIN").is_err() {
                std::env::set_var("OPENSSL_BIN", openssl_dir.join("bin/openssl"));
            }
            // Probe lib64 first (common on 64-bit distros), then fall back to lib.
            if std::env::var("OPENSSL_LIB").is_err() {
                let lib64 = openssl_dir.join("lib64");
                let lib = openssl_dir.join("lib");
                if lib64.is_dir() {
                    std::env::set_var("OPENSSL_LIB", lib64);
                } else if lib.is_dir() {
                    std::env::set_var("OPENSSL_LIB", lib);
                } else {
                    log::warn!(
                        "neither {} nor {} exists — OPENSSL_LIB not set",
                        lib64.display(),
                        lib.display()
                    );
                }
            }
            if std::env::var("OPENSSL_DIR").is_err() {
                std::env::set_var("OPENSSL_DIR", &openssl_dir);
            }

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
