// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NGINX integration test runner.
//!
//! End-to-end test that verifies the azihsm OpenSSL provider works correctly
//! with NGINX for TLS termination.
//!
//! Key material, generated OpenSSL configs, and the NGINX config are all
//! placed under `target/test-keymat/nginx/` — the same isolation pattern
//! used by the CLI and CAPI test suites.  The xtask cleans
//! `target/test-keymat/` before each integration run for fresh-per-run
//! isolation.
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
    use std::fs;
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
        let keymat_dir = workspace_root
            .join("target")
            .join("test-keymat")
            .join("nginx");
        fs::create_dir_all(&keymat_dir).expect("Failed to create target/test-keymat/nginx");

        let provider_path = get_provider_path(workspace_root);
        let provider_so = provider_path.join("azihsm_provider.so");

        generate_provider_conf(&keymat_dir, &provider_so);
        generate_cli_conf(&keymat_dir, &provider_so);
        generate_nginx_conf(&keymat_dir);

        run_setup(testfiles_dir, &keymat_dir)?;

        // Install nginx.conf and start the daemon with the generated
        // OPENSSL_CONF pointing into the keymat directory.
        let nginx_conf = keymat_dir.join("nginx.conf");
        start_nginx(&keymat_dir, &nginx_conf)?;

        let mut first_failure: Option<Failed> = None;
        for script in ASSERTION_SCRIPTS {
            let script_path = testfiles_dir.join(script);
            match run_test_script(&script_path, &keymat_dir, &provider_so, &nginx_conf) {
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
    fn get_workspace_root() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        // crate is at plugins/ossl_prov/integration-tests/nginx (4 levels deep)
        Path::new(&manifest_dir)
            .ancestors()
            .nth(4)
            .expect("CARGO_MANIFEST_DIR does not have enough ancestors")
            .to_path_buf()
    }

    /// Resolves the provider search path (absolute) and verifies the provider
    /// `.so` exists there.
    ///
    /// Uses `PROVIDER_PATH` if set, otherwise defaults to `target/debug` under
    /// the workspace root.  Matches the convention used by CLI (`env.sh`) and
    /// CAPI (`get_provider_path()`).
    fn get_provider_path(workspace_root: &Path) -> PathBuf {
        let path = match env::var("PROVIDER_PATH") {
            Ok(p) if !p.is_empty() => {
                let p = PathBuf::from(p);
                if p.is_relative() {
                    workspace_root.join(p)
                } else {
                    p
                }
            }
            _ => workspace_root.join("target").join("debug"),
        };

        let provider_so = path.join("azihsm_provider.so");
        assert!(
            provider_so.exists(),
            "\n\
             azihsm_provider.so not found at {}\n\
             \n\
             Build the provider first:\n\
             \n\
                 cargo build -p azihsm_ossl_provider --features mock,provider\n",
            provider_so.display(),
        );

        path
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

    /// Generates the OpenSSL provider config for NGINX runtime.
    ///
    /// This config is pointed to by `OPENSSL_CONF` when NGINX runs.  It
    /// activates the `default`, `base`, and `azihsm_provider` providers with
    /// all key material paths pointing into the keymat directory.
    ///
    /// Unlike the static `nginx-example/openssl-provider.cnf` (which uses
    /// hardcoded system paths), this is generated at runtime with absolute
    /// paths — the same approach as CLI's `env.sh` and CAPI's
    /// `generate_openssl_conf()`.
    fn generate_provider_conf(keymat_dir: &Path, provider_so: &Path) {
        let conf_path = keymat_dir.join("openssl-provider.cnf");
        let content = format!(
            "\
# Generated by nginx_tests.rs — do not edit.
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
base = base_sect
azihsm_provider = azihsm_provider_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[azihsm_provider_sect]
module = {module}
activate = 1
azihsm-bmk-path = {dir}/bmk.bin
azihsm-muk-path = {dir}/muk.bin
azihsm-obk-path = {dir}/obk.bin
azihsm-obk-source = caller
azihsm-pota-source = caller
azihsm-pota-private-key-path = {dir}/pota_private_key.der
azihsm-pota-public-key-path = {dir}/pota_public_key.der
",
            module = provider_so.display(),
            dir = keymat_dir.display(),
        );
        fs::write(&conf_path, content).expect("Failed to write openssl-provider.cnf");
    }

    /// Generates the OpenSSL CLI config for key generation commands.
    ///
    /// Identical to the provider config but adds `default_properties` so
    /// that CLI commands (genpkey, req) prefer the azihsm provider without
    /// needing explicit `-propquery` flags.
    fn generate_cli_conf(keymat_dir: &Path, provider_so: &Path) {
        let conf_path = keymat_dir.join("openssl-cli.cnf");
        let content = format!(
            "\
# Generated by nginx_tests.rs — do not edit.
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
default = default_sect
base = base_sect
azihsm_provider = azihsm_provider_sect

[default_sect]
activate = 1

[base_sect]
activate = 1

[azihsm_provider_sect]
module = {module}
activate = 1
azihsm-bmk-path = {dir}/bmk.bin
azihsm-muk-path = {dir}/muk.bin
azihsm-obk-path = {dir}/obk.bin
azihsm-obk-source = caller
azihsm-pota-source = caller
azihsm-pota-private-key-path = {dir}/pota_private_key.der
azihsm-pota-public-key-path = {dir}/pota_public_key.der

[algorithm_sect]
default_properties = ?provider=azihsm
",
            module = provider_so.display(),
            dir = keymat_dir.display(),
        );
        fs::write(&conf_path, content).expect("Failed to write openssl-cli.cnf");
    }

    /// Generates the NGINX config with absolute paths to key material.
    ///
    /// The certificate and masked key paths point into the keymat directory
    /// instead of the static `/etc/azihsm/` paths used by the production
    /// `nginx-example/` config.
    fn generate_nginx_conf(keymat_dir: &Path) {
        let conf_path = keymat_dir.join("nginx.conf");
        let content = format!(
            "\
# Generated by nginx_tests.rs — do not edit.
worker_processes 1;

env OPENSSL_CONF;
env AZIHSM_CREDENTIALS_ID;
env AZIHSM_CREDENTIALS_PIN;

error_log /var/log/nginx/error.log info;
pid       /run/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_tickets off;

    server {{
        listen      8443 ssl;
        server_name localhost;

        ssl_certificate     {dir}/server.crt;
        ssl_certificate_key \"store:azihsm://{dir}/masked_key_p384.bin;type=ec\";

        location / {{
            default_type text/plain;
            return 200 'nginx + azihsm provider\\n';
        }}

        location /health {{
            default_type application/json;
            return 200 '{{\"status\":\"healthy\",\"provider\":\"azihsm\"}}\\n';
        }}
    }}
}}
",
            dir = keymat_dir.display(),
        );
        fs::write(&conf_path, content).expect("Failed to write nginx.conf");
    }

    /// Runs `setup.sh` to generate key material into the keymat directory.
    ///
    /// The script receives the keymat directory as its first argument.
    /// It generates base key material (credentials, OBK, POTA) without
    /// the provider, then sets `OPENSSL_CONF` to the generated
    /// `openssl-provider.cnf` for the `genpkey` and `req` commands that
    /// need the azihsm provider.  All files are written directly into
    /// the keymat directory — no system paths involved.
    fn run_setup(testfiles_dir: &Path, keymat_dir: &Path) -> Result<(), Failed> {
        let setup_script = testfiles_dir.join("setup.sh");
        assert!(
            setup_script.exists(),
            "setup.sh not found at {}",
            setup_script.display()
        );

        let mut cmd = Command::new("bash");
        cmd.arg(&setup_script);
        cmd.arg(keymat_dir);
        cmd.current_dir(keymat_dir);

        if let Ok(val) = env::var("OPENSSL_BIN") {
            cmd.env("OPENSSL_BIN", val);
        }

        // Set LD_LIBRARY_PATH to the OpenSSL lib dir so setup.sh's openssl
        // binary can find libcrypto.so.
        if let Ok(val) = env::var("OPENSSL_LIB") {
            cmd.env("LD_LIBRARY_PATH", val);
        } else if let Ok(val) = env::var("LD_LIBRARY_PATH") {
            cmd.env("LD_LIBRARY_PATH", val);
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
    fn start_nginx(keymat_dir: &Path, nginx_conf: &Path) -> Result<(), Failed> {
        let openssl_conf = keymat_dir.join("openssl-provider.cnf");

        // Install generated nginx.conf where NGINX can find it
        let status = Command::new("sudo")
            .args(["cp"])
            .arg(nginx_conf)
            .arg("/etc/nginx/nginx.conf")
            .status()
            .expect("Failed to copy nginx.conf");
        if !status.success() {
            return Err("Failed to install nginx.conf".into());
        }

        let creds = credential_env();
        let env_args: Vec<String> =
            std::iter::once(format!("OPENSSL_CONF={}", openssl_conf.display()))
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
    /// Scripts receive useful context via environment variables:
    /// - `KEYMAT_DIR`: path to the key material directory
    /// - `PROVIDER_SO`: absolute path to `azihsm_provider.so`
    /// - `NGINX_CONF`: path to the generated `nginx.conf`
    ///
    /// `LD_LIBRARY_PATH` is stripped so test scripts use system OpenSSL.
    fn run_test_script(
        script_path: &Path,
        keymat_dir: &Path,
        provider_so: &Path,
        nginx_conf: &Path,
    ) -> Result<(), Failed> {
        let output = Command::new("bash")
            .arg(script_path)
            .env_remove("LD_LIBRARY_PATH")
            .env("KEYMAT_DIR", keymat_dir)
            .env("PROVIDER_SO", provider_so)
            .env("NGINX_CONF", nginx_conf)
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
