// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use clap::Parser;
use clap::ValueEnum;

use crate::Xtask;
use crate::XtaskCtx;

/// Which provider integration suite(s) to run.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Suite {
    /// OpenSSL CLI tests via lit (`provider-integration-tests-cli`).
    Cli,
    /// OpenSSL C API tests via libtest-mimic + gtest (`provider-integration-tests-capi`).
    Capi,
    /// NGINX tests via libtest-mimic (`provider-integration-tests-nginx`).
    Nginx,
    /// Run all three suites in order: cli, capi, nginx.
    All,
}

/// Run the OpenSSL provider integration tests.
///
/// Discovers OpenSSL via [`crate::host_openssl::check_openssl`] (respects
/// `OPENSSL_DIR` first, falls back to `pkg-config` and well-known
/// prefixes).  Cleans `target/test-keymat/` before each run for fresh
/// per-run isolation.  Sets `OPENSSL_BIN` / `OPENSSL_LIB` / `OPENSSL_DIR`
/// for the test harnesses if they aren't already set.
///
/// The provider stack itself is **not** built here — callers must build it
/// into `target/debug` (`cargo build -p azihsm_ossl_provider --features mock`)
/// beforehand.  Keeping the build out means a partial run (`--suite nginx`)
/// doesn't recompile the world.
#[derive(Parser)]
#[clap(about = "Run Integration Tests")]
pub struct IntegrationTest {
    /// Which suite to run.  Defaults to `all` (cli + capi + nginx).
    #[clap(long, value_enum, default_value_t = Suite::All)]
    pub suite: Suite,
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
            // A caller may export these as an empty string (env.sh sets
            // OPENSSL_LIB="" to mean "set but empty"); treat empty as unset.
            let unset_or_empty =
                |key: &str| std::env::var(key).map(|v| v.is_empty()).unwrap_or(true);

            // check_openssl() respects OPENSSL_DIR first and would treat an
            // empty value as a (bad) path; drop it so the fallback discovery
            // (pkg-config, well-known prefixes) kicks in.
            if std::env::var("OPENSSL_DIR").is_ok_and(|v| v.is_empty()) {
                std::env::remove_var("OPENSSL_DIR");
            }
            let openssl_dir = crate::host_openssl::check_openssl()?;

            if unset_or_empty("OPENSSL_BIN") {
                let bin = openssl_dir.join("bin/openssl");
                anyhow::ensure!(
                    bin.is_file(),
                    "openssl binary not found at {}; install openssl or set OPENSSL_BIN",
                    bin.display()
                );
                std::env::set_var("OPENSSL_BIN", bin);
            }
            if unset_or_empty("OPENSSL_DIR") {
                std::env::set_var("OPENSSL_DIR", &openssl_dir);
            }

            // Compute the OpenSSL lib dir for both `OPENSSL_LIB` (read by the
            // env.sh / CAPI / NGINX harnesses) and `LD_LIBRARY_PATH` (read
            // directly by the dynamic linker for every `openssl` subprocess
            // spawn).  Both are necessary: the openssl binary itself needs
            // libcrypto.so.3 to load (LD_LIBRARY_PATH), and the harnesses
            // need to know which lib dir to forward (OPENSSL_LIB).  Probe
            // lib64 first (RHEL/Fedora), then fall back to lib.  `target/debug`
            // is appended for `libazihsm_api_native.so` resolution.
            let cargo_debug = _ctx.root.join("target").join("debug");
            let openssl_lib_dir = {
                let lib64 = openssl_dir.join("lib64");
                let lib = openssl_dir.join("lib");
                if lib64.is_dir() {
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
                }
            };
            if let Some(ref p) = openssl_lib_dir {
                let combined = format!("{}:{}", p.display(), cargo_debug.display());
                // env.sh derives LD_LIBRARY_PATH from OPENSSL_LIB, so a
                // caller-supplied value must still include target/debug for
                // libazihsm_api_native.so resolution.
                let dbg = cargo_debug.display().to_string();
                match std::env::var("OPENSSL_LIB") {
                    Ok(v) if !v.is_empty() => {
                        if !v.split(':').any(|seg| seg == dbg) {
                            std::env::set_var("OPENSSL_LIB", format!("{v}:{dbg}"));
                        }
                    }
                    _ => std::env::set_var("OPENSSL_LIB", &combined),
                }
                // Always prepend to LD_LIBRARY_PATH so the custom openssl
                // binary's libcrypto resolves to our install, not the system
                // one (which may lack newer symbols).  Prepending keeps any
                // existing LD_LIBRARY_PATH content reachable as a fallback.
                let existing = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
                let new_ld = if existing.is_empty() {
                    combined
                } else {
                    format!("{combined}:{existing}")
                };
                std::env::set_var("LD_LIBRARY_PATH", new_ld);
            }

            // Test key material is regenerated per run by each harness; the
            // wrapping clean below ensures no stale state from a prior run
            // leaks across processes.
            let keymat_dir = _ctx.root.join("target").join("test-keymat");
            if keymat_dir.exists() {
                std::fs::remove_dir_all(&keymat_dir)?;
                log::trace!(
                    "cleaned previous test key material at {}",
                    keymat_dir.display()
                );
            }

            let run_pkg = |pkg: &str, ctx: XtaskCtx| -> anyhow::Result<()> {
                crate::nextest::Nextest {
                    features: Some("integration".to_string()),
                    package: Some(pkg.to_string()),
                    no_default_features: false,
                    filterset: None,
                    profile: Some("ci-provider-integration".to_string()),
                    exclude: vec![],
                }
                .run(ctx)
            };

            match self.suite {
                Suite::Cli => run_pkg("provider-integration-tests-cli", _ctx),
                Suite::Capi => run_pkg("provider-integration-tests-capi", _ctx),
                Suite::Nginx => run_pkg("provider-integration-tests-nginx", _ctx),
                Suite::All => {
                    run_pkg("provider-integration-tests-cli", _ctx.clone())?;
                    run_pkg("provider-integration-tests-capi", _ctx.clone())?;
                    run_pkg("provider-integration-tests-nginx", _ctx)
                }
            }
        }
    }
}
