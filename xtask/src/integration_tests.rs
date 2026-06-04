// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;

use crate::Xtask;
use crate::XtaskCtx;

/// Xtask to run integration tests.
///
/// Currently a no-op. The provider integration test passes (CLI, CAPI,
/// nginx) are temporarily disabled while the OpenSSL provider build
/// coupling with `libazihsm_api_native` is being reworked. The command
/// remains in the xtask surface so CI / scripted invocations stay
/// stable; it logs a skip notice and returns success.
///
/// Re-enable by restoring the nextest invocations in this file once
/// the build coupling rework lands.
#[derive(Parser)]
<<<<<<< HEAD
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
            for package in [
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
=======
#[clap(about = "Run Integration Tests (currently disabled)")]
pub struct IntegrationTest {}

impl Xtask for IntegrationTest {
    fn run(self, _ctx: XtaskCtx) -> anyhow::Result<()> {
        log::warn!(
            "skipping provider integration tests: temporarily disabled \
             while OpenSSL provider build coupling with libazihsm_api_native \
             is reworked. Re-enable by restoring the nextest invocations in \
             xtask/src/integration_tests.rs once the rework lands."
        );
>>>>>>> main
        Ok(())
    }
}
