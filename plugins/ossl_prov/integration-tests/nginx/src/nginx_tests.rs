// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NGINX integration test runner.
//!
//! End-to-end test that verifies the azihsm OpenSSL provider works correctly
//! with NGINX for TLS termination.  Unlike the cli and capi test suites
//! (which use isolated `target/test-keymat/` directories), this suite deploys
//! to **system paths** (`/etc/azihsm/`, `/var/lib/azihsm/`,
//! `/usr/lib/x86_64-linux-gnu/ossl-modules/`) to mirror a real production
//! deployment where NGINX loads the provider via `OPENSSL_CONF`.
//!
//! All assertions are grouped into a **single nextest Trial** because they
//! share a running NGINX daemon.  The cli and capi suites can expose many
//! independent trials because each test is stateless — here the daemon is
//! shared state that cannot be started/stopped per process without port
//! conflicts and ordering issues.

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

    /// Assertion scripts executed in order after NGINX is started.
    ///
    /// These run inside a single nextest Trial (process) because they depend
    /// on a shared NGINX daemon.  nextest runs each Trial in its own process
    /// with no ordering guarantee, so splitting into separate Trials would
    /// require each process to manage its own NGINX lifecycle independently.
    /// The negative test must run last — it stops NGINX and removes the
    /// provider.
    const ASSERTION_SCRIPTS: &[&str] = &[
        "verify_tls_endpoint.sh",
        "verify_cert_properties.sh",
        "negative_provider_required.sh",
    ];

    /// Run the full NGINX integration test suite.
    pub fn run(args: Arguments) {
        let testfiles_dir = get_testfiles_dir();
        let workspace_root = get_workspace_root();

        let tests = vec![Trial::test("nginx_integration", move || {
            run_all(&testfiles_dir, &workspace_root)
        })];

        libtest_mimic::run(&args, tests).exit();
    }

    /// Runs setup, starts NGINX, executes all assertion scripts in order,
    /// then tears down.  Reports per-script pass/fail to stdout.
    fn run_all(testfiles_dir: &Path, workspace_root: &Path) -> Result<(), Failed> {
        run_setup(testfiles_dir, workspace_root)?;
        start_nginx()?;

        let mut first_failure: Option<Failed> = None;
        for script in ASSERTION_SCRIPTS {
            let script_path = testfiles_dir.join(script);
            match run_test_script(&script_path) {
                Ok(()) => println!("[PASS] {script}"),
                Err(e) => {
                    println!("[FAIL] {script}");
                    if first_failure.is_none() {
                        first_failure = Some(e);
                    }
                }
            }
        }

        stop_nginx();

        match first_failure {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn get_testfiles_dir() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        PathBuf::from(manifest_dir).join("testfiles")
    }

    /// Resolves the workspace root from `CARGO_MANIFEST_DIR`.
    /// CI generates base key material (obk.bin, pota keys, credentials)
    /// in the workspace root; setup.sh runs from there to find them.
    fn get_workspace_root() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        // crate is at plugins/ossl_prov/integration-tests/nginx (4 levels deep)
        Path::new(&manifest_dir)
            .ancestors()
            .nth(4)
            .expect("CARGO_MANIFEST_DIR does not have enough ancestors")
            .to_path_buf()
    }

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

    /// Runs `setup.sh` from the workspace root to generate keys, certs,
    /// and install key material to system paths.
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

    /// Validates the NGINX config and starts the daemon.
    ///
    /// Uses `sudo env -u LD_LIBRARY_PATH` to strip the custom OpenSSL 3.0.3
    /// lib path that nextest inherits — NGINX links against system OpenSSL.
    /// Explicit `K=V` args ensure `OPENSSL_CONF` and credentials reach the
    /// NGINX process regardless of sudo's `env_reset` policy.
    fn start_nginx() -> Result<(), Failed> {
        let openssl_conf = env::var("OPENSSL_CONF")
            .unwrap_or_else(|_| "/etc/azihsm/openssl-provider.cnf".to_string());

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

        let creds = credential_env();
        let env_args: Vec<String> = std::iter::once(format!("OPENSSL_CONF={openssl_conf}"))
            .chain(creds.iter().map(|(k, v)| format!("{k}={v}")))
            .collect();

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

        std::thread::sleep(std::time::Duration::from_secs(2));
        Ok(())
    }

    /// Stops NGINX (best-effort — the negative test may have already stopped it).
    fn stop_nginx() {
        let _ = Command::new("sudo").args(["nginx", "-s", "stop"]).status();
    }

    /// Executes a single test shell script.
    ///
    /// `LD_LIBRARY_PATH` is stripped so test scripts use system OpenSSL
    /// (the custom 3.0.3 build is only needed by `setup.sh`).
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
