// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NGINX integration test runner.
//!
//! This module provides a Rust-based test harness that manages the full NGINX
//! lifecycle: key generation, certificate creation, key material installation,
//! NGINX startup, assertion tests, and teardown.
//!
//! It uses `libtest_mimic` to integrate the test into the Rust test
//! infrastructure, allowing it to be run with `cargo nextest`.
//!
//! Because nextest runs each test in its own process, the entire NGINX
//! lifecycle is wrapped in a single test to avoid conflicts from multiple
//! nginx instances or redundant setup/teardown.

/// Entry point for the NGINX test runner.
///
/// When built without the `integration` feature the binary is a no-op so that
/// `cargo clippy --all-targets` (which doesn't pass `--features integration`)
/// can still compile the crate.
fn main() {
    #[cfg(feature = "integration")]
    {
        let args = libtest_mimic::Arguments::from_args();
        integration::run(args);
    }
}

#[cfg(feature = "integration")]
mod integration {
    #![allow(clippy::unwrap_used)]

    use std::env;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;

    use libtest_mimic::*;

    /// Ordered list of assertion scripts to run after NGINX is started.
    /// The negative test must run last as it stops NGINX and removes the
    /// provider.
    const ASSERTION_SCRIPTS: &[&str] = &[
        "verify_tls_endpoint.sh",
        "verify_cert_properties.sh",
        "negative_provider_required.sh",
    ];

    /// Run the full NGINX integration test suite.
    ///
    /// A single test wraps the entire lifecycle (setup → nginx start →
    /// assertions → teardown) so that nextest's process-per-test model
    /// does not cause conflicts from multiple nginx instances.
    pub fn run(args: Arguments) {
        let testfiles_dir = get_testfiles_dir();
        let workspace_root = get_workspace_root();

        let tests = vec![Trial::test("nginx_integration", move || {
            run_all(&testfiles_dir, &workspace_root)
        })];

        libtest_mimic::run(&args, tests).exit();
    }

    /// Runs setup, starts nginx, executes all assertion scripts in order,
    /// then tears down.
    fn run_all(testfiles_dir: &Path, workspace_root: &Path) -> Result<(), Failed> {
        // --- Setup: key generation, cert creation, key material install ------
        run_setup(testfiles_dir, workspace_root)?;
        start_nginx()?;

        // --- Run assertion scripts in order ----------------------------------
        let mut first_failure: Option<Failed> = None;
        for script in ASSERTION_SCRIPTS {
            let script_path = testfiles_dir.join(script);
            if let Err(e) = run_test_script(&script_path) {
                if first_failure.is_none() {
                    first_failure = Some(e);
                }
                // Continue running remaining scripts for diagnostic value,
                // but the negative test may stop nginx.
            }
        }

        // --- Teardown: stop nginx (best-effort, negative test may have
        // already stopped it) -------------------------------------------------
        stop_nginx();

        match first_failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Returns the absolute path to the `testfiles/` directory.
    fn get_testfiles_dir() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        PathBuf::from(manifest_dir).join("testfiles")
    }

    /// Returns the workspace root directory.
    ///
    /// The CI "Generate dev key material" step creates `obk.bin`,
    /// `pota_private_key.der`, etc. in the workspace root.  We resolve it
    /// from `CARGO_MANIFEST_DIR` (which points at the crate directory) by
    /// walking up the ancestor chain.
    fn get_workspace_root() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        // crate is at plugins/ossl_prov/integration-tests/nginx (4 levels deep)
        Path::new(&manifest_dir)
            .ancestors()
            .nth(4)
            .expect("CARGO_MANIFEST_DIR does not have enough ancestors")
            .to_path_buf()
    }

    /// Returns credential environment variables for subprocesses.
    fn credential_env() -> Vec<(&'static str, String)> {
        vec![
            (
                "AZIHSM_CREDENTIALS_ID",
                env::var("AZIHSM_CREDENTIALS_ID")
                    .unwrap_or_else(|_| "70fcf730b8764238b8358010ce8a3f76".to_string()),
            ),
            (
                "AZIHSM_CREDENTIALS_PIN",
                env::var("AZIHSM_CREDENTIALS_PIN")
                    .unwrap_or_else(|_| "db3dc77fc22e430080d41b31b6f04800".to_string()),
            ),
        ]
    }

    /// Runs the `setup.sh` script to generate keys, certs, and install key
    /// material.  The script runs from the workspace root so it can find
    /// the base key material files generated by CI.
    fn run_setup(testfiles_dir: &Path, workspace_root: &Path) -> Result<(), Failed> {
        let setup_script = testfiles_dir.join("setup.sh");
        assert!(
            setup_script.exists(),
            "setup.sh not found at {}",
            setup_script.display()
        );

        let mut cmd = Command::new("bash");
        cmd.arg(&setup_script);
        cmd.current_dir(workspace_root);

        // Pass through required environment variables
        if let Ok(val) = env::var("OPENSSL_BIN") {
            cmd.env("OPENSSL_BIN", val);
        }
        if let Ok(val) = env::var("LD_LIBRARY_PATH") {
            cmd.env("LD_LIBRARY_PATH", val);
        }
        if let Ok(val) = env::var("OPENSSL_LIB") {
            cmd.env("OPENSSL_LIB", val);
        }
        if let Ok(val) = env::var("PROVIDER_PATH") {
            cmd.env("PROVIDER_PATH", val);
        }
        for (key, val) in credential_env() {
            cmd.env(key, val);
        }

        let output = cmd.output().expect("Failed to run setup.sh");
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "setup.sh failed (exit code: {})\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into())
        }
    }

    /// Validates the NGINX config and starts NGINX.
    fn start_nginx() -> Result<(), Failed> {
        let openssl_conf = env::var("OPENSSL_CONF")
            .unwrap_or_else(|_| "/etc/azihsm/openssl-provider.cnf".to_string());

        // Install nginx.conf
        let status = Command::new("sudo")
            .args([
                "cp",
                "/etc/azihsm/nginx.conf.template",
                "/etc/nginx/nginx.conf",
            ])
            .status()
            .expect("Failed to copy nginx.conf");
        if !status.success() {
            return Err("Failed to install nginx.conf".into());
        }

        // Build env args for sudo: sudo env -u LD_LIBRARY_PATH K=V ... nginx
        // - `env -u LD_LIBRARY_PATH` strips the custom OpenSSL 3.0.3 lib
        //   path that nextest inherits; nginx uses system OpenSSL instead.
        // - Explicit K=V ensures OPENSSL_CONF and credentials reach the
        //   nginx process regardless of sudo env_reset policy.
        let creds = credential_env();
        let env_args: Vec<String> = std::iter::once(format!("OPENSSL_CONF={openssl_conf}"))
            .chain(creds.iter().map(|(k, v)| format!("{k}={v}")))
            .collect();

        // Validate config
        let mut validate = vec![
            "env".to_string(),
            "-u".to_string(),
            "LD_LIBRARY_PATH".to_string(),
        ];
        validate.extend(env_args.clone());
        validate.extend(["nginx", "-t", "-c", "/etc/nginx/nginx.conf"].map(String::from));
        let status = Command::new("sudo")
            .args(&validate)
            .status()
            .expect("Failed to run nginx -t");
        if !status.success() {
            return Err("nginx config validation failed (nginx -t)".into());
        }

        // Start nginx
        let mut start = vec![
            "env".to_string(),
            "-u".to_string(),
            "LD_LIBRARY_PATH".to_string(),
        ];
        start.extend(env_args);
        start.extend(["nginx", "-c", "/etc/nginx/nginx.conf"].map(String::from));
        let status = Command::new("sudo")
            .args(&start)
            .status()
            .expect("Failed to start nginx");
        if !status.success() {
            return Err("nginx failed to start".into());
        }

        // Allow time for nginx to become ready
        std::thread::sleep(std::time::Duration::from_secs(2));
        Ok(())
    }

    /// Stops NGINX (best-effort — may already be stopped by negative test).
    fn stop_nginx() {
        let _ = Command::new("sudo").args(["nginx", "-s", "stop"]).status();
    }

    /// Executes a single test shell script and returns the result.
    ///
    /// `LD_LIBRARY_PATH` is removed so test scripts use system OpenSSL
    /// (not the custom 3.0.3 build used only by setup.sh for key generation).
    fn run_test_script(script_path: &Path) -> Result<(), Failed> {
        let output = Command::new("bash")
            .arg(script_path)
            .env_remove("LD_LIBRARY_PATH")
            .envs(credential_env())
            .output()
            .expect("Failed to run test script");

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{} failed (exit code: {})\nstdout: {}\nstderr: {}",
                script_path.display(),
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            )
            .into())
        }
    }
}
