// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;

use crate::nextest;
use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests
#[derive(Parser)]
#[clap(about = "Run Integration Tests")]
pub struct IntegrationTest {}

impl Xtask for IntegrationTest {
    fn run(self, ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("start testing");

        if !cfg!(target_os = "linux") {
            log::warn!("skipping provider integration tests: only supported on Linux");
            return Ok(());
        }

        let openssl_dir = crate::openssl_install::ensure_openssl()?;

        // Derive OPENSSL_BIN if not set — CLI integration tests (env.sh) hard-require it.
        if std::env::var("OPENSSL_BIN").is_err() {
            std::env::set_var("OPENSSL_BIN", openssl_dir.join("bin/openssl"));
        }
        // Derive OPENSSL_LIB if not set — CLI env.sh uses it to set LD_LIBRARY_PATH.
        if std::env::var("OPENSSL_LIB").is_err() {
            std::env::set_var("OPENSSL_LIB", openssl_dir.join("lib"));
        }
        // Ensure OPENSSL_DIR is set for the CAPI build script and test binary.
        if std::env::var("OPENSSL_DIR").is_err() {
            std::env::set_var("OPENSSL_DIR", &openssl_dir);
        }

        // Clean previous test key material for fresh-per-run isolation
        let keymat_dir = ctx.root.join("target").join("test-keymat");
        if keymat_dir.exists() {
            std::fs::remove_dir_all(&keymat_dir)?;
            log::trace!(
                "cleaned previous test key material at {}",
                keymat_dir.display()
            );
        }

        // CLI-based integration tests (openssl command-line)
        let cli_tests = nextest::Nextest {
            features: Some("integration".to_string()),
            package: Some("provider-integration-tests-cli".to_string()),
            no_default_features: false,
            filterset: None,
            profile: Some("ci-provider-integration".to_string()),
            exclude: vec![],
        };
        cli_tests.run(ctx.clone())?;

        // C API integration tests (OpenSSL EVP API via gtest)
        let capi_tests = nextest::Nextest {
            features: Some("integration".to_string()),
            package: Some("provider-integration-tests-capi".to_string()),
            no_default_features: false,
            filterset: None,
            profile: Some("ci-provider-integration".to_string()),
            exclude: vec![],
        };
        capi_tests.run(ctx.clone())?;

        // NGINX integration tests (end-to-end TLS with provider)
        let nginx_tests = nextest::Nextest {
            features: Some("integration".to_string()),
            package: Some("provider-integration-tests-nginx".to_string()),
            no_default_features: false,
            filterset: None,
            profile: Some("ci-provider-integration".to_string()),
            exclude: vec![],
        };
        nginx_tests.run(ctx)
    }
}
