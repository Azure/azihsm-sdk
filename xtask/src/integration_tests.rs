// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use std::fs;

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

        // Clean previous test key material for fresh-per-run isolation
        let keymat_dir = ctx.root.join("target").join("test-keymat");
        if keymat_dir.exists() {
            fs::remove_dir_all(&keymat_dir)?;
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
        capi_tests.run(ctx)
    }
}
