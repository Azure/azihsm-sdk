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
    /// Whether to run tests with code coverage enabled
    #[clap(long)]
    pub coverage: bool,
}

impl Xtask for IntegrationTest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::trace!("start integration tests");

        #[cfg(not(target_os = "linux"))]
        {
            log::warn!("skipping provider integration tests: only supported on Linux");
        }

        #[cfg(target_os = "linux")]
        {
            let openssl_dir = crate::openssl_install::check_openssl()?;

            if std::env::var("OPENSSL_BIN").is_err() {
                std::env::set_var("OPENSSL_BIN", openssl_dir.join("bin/openssl"));
            }
            if std::env::var("OPENSSL_LIB").is_err() {
                std::env::set_var("OPENSSL_LIB", openssl_dir.join("lib"));
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

            let mut tests = Vec::new();

            // define test parameters
            for package in vec![
                "provider-integration-tests-cli",
                "provider-integration-tests-capi",
                "provider-integration-tests-nginx",
            ] {
                let test = crate::nextest::Nextest {
                    features: Some("integration".to_string()),
                    package: Some(package.to_string()),
                    no_default_features: false,
                    filterset: None,
                    profile: Some("ci-provider-integration".to_string()),
                    exclude: vec![],
                };
                tests.push(test);
            }

            // run tests
            for test in tests {
                if self.coverage {
                    crate::coverage::Coverage::from(test).run(_ctx.clone())?;
                } else {
                    test.run(_ctx.clone())?;
                }
            }
        }

        log::trace!("finished integration tests");
        Ok(())
    }
}
