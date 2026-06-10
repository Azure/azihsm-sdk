// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C++ test runner for OpenSSL provider integration tests.
//!
//! This module provides a Rust-based test harness that discovers and executes
//! C++ Google Test (gtest) tests. It uses `libtest_mimic` to integrate C++
//! tests into the Rust test infrastructure, allowing them to be run with
//! standard Rust test tools like `cargo test`.
//!
//! The tests exercise the azihsm OpenSSL provider through the OpenSSL C API
//! (EVP_PKEY, EVP_DigestSign/Verify, etc.) rather than the command-line tool,
//! enabling testing of session-based keys that cannot be tested via the CLI.

/// Entry point for the C++ test runner.
///
/// When built without the `integration` feature the binary is a no-op so that
/// `cargo clippy --all-targets` (which doesn't pass `--features integration`)
/// can still compile the crate.
fn main() {
    #[cfg(feature = "integration")]
    {
        let args = libtest_mimic::Arguments::from_args();
        let (tests, _keymat_dir) = integration::get_tests();
        libtest_mimic::run(&args, tests).exit();
    }
}

#[cfg(feature = "integration")]
mod integration {
    #![allow(clippy::unwrap_used)]

    use std::env;
    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;
    use std::process::Stdio;

    use libtest_mimic::*;

    /// Retrieves the list of all available C++ tests.
    ///
    /// Returns the test list and the key material directory path (which must
    /// outlive the test closures so the files remain available during execution).
    pub fn get_tests() -> (Vec<Trial>, PathBuf) {
        let workspace_root = get_workspace_root();
        let (credentials, keymat_dir) = generate_dev_key_material(&workspace_root);
        let resiliency_dir = get_resiliency_storage_dir(&keymat_dir);
        let test_path = get_test_binary_path();
        let provider_path = get_provider_path(&workspace_root);
        generate_openssl_conf(&keymat_dir, &provider_path);
        let ld_library_path = build_ld_library_path(&provider_path);
        let test_list = list_gtests(&test_path, &ld_library_path, &credentials, &keymat_dir);
        let tests = parse_gtest_list(
            &test_list,
            test_path,
            ld_library_path,
            credentials,
            keymat_dir.clone(),
            provider_path,
            resiliency_dir,
        );
        (tests, keymat_dir)
    }

    /// Returns the workspace root directory.
    fn get_workspace_root() -> PathBuf {
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        Path::new(&manifest_dir)
            .ancestors()
            .nth(4)
            .expect("CARGO_MANIFEST_DIR does not have enough ancestors")
            .to_path_buf()
    }

    /// Resolves the OpenSSL binary from `OPENSSL_BIN` or `OPENSSL_DIR/bin/openssl`.
    fn find_openssl_bin() -> PathBuf {
        if let Ok(bin) = env::var("OPENSSL_BIN") {
            let p = PathBuf::from(&bin);
            assert!(p.is_file(), "OPENSSL_BIN does not exist: {bin}");
            return p;
        }
        if let Ok(dir) = env::var("OPENSSL_DIR") {
            let p = PathBuf::from(&dir).join("bin").join("openssl");
            assert!(
                p.is_file(),
                "openssl binary not found at {}, and OPENSSL_BIN is not set",
                p.display()
            );
            return p;
        }
        panic!("Neither OPENSSL_BIN nor OPENSSL_DIR is set — cannot generate dev key material");
    }

    /// Default credential ID (hex-encoded UUID, matching `env.sh`).
    const DEFAULT_CREDENTIALS_ID: &str = "70fcf730b8764238b8358010ce8a3f76";
    /// Default credential PIN (hex-encoded UUID, matching `env.sh`).
    const DEFAULT_CREDENTIALS_PIN: &str = "db3dc77fc22e430080d41b31b6f04800";

    /// Credential env var values to pass to gtest subprocesses.
    #[derive(Clone)]
    struct Credentials {
        id: String,
        pin: String,
    }

    /// Generates dev credential and key material files in an isolated directory
    /// under `target/test-keymat/capi/`.  Returns credential values and the
    /// key material directory path.
    ///
    /// Files are always generated fresh (no `if !exists` guards) because the
    /// xtask cleans `target/test-keymat/` before each integration test run.
    fn generate_dev_key_material(workspace_root: &Path) -> (Credentials, PathBuf) {
        let credentials = Credentials {
            id: env::var("AZIHSM_CREDENTIALS_ID")
                .unwrap_or_else(|_| DEFAULT_CREDENTIALS_ID.to_string()),
            pin: env::var("AZIHSM_CREDENTIALS_PIN")
                .unwrap_or_else(|_| DEFAULT_CREDENTIALS_PIN.to_string()),
        };

        let keymat_dir = workspace_root
            .join("target")
            .join("test-keymat")
            .join("capi");
        fs::create_dir_all(&keymat_dir).expect("Failed to create test-keymat/capi directory");

        // Credential ID binary file
        let cred_id_data: [u8; 16] = [
            0x70, 0xFC, 0xF7, 0x30, 0xB8, 0x76, 0x42, 0x38, 0xB8, 0x35, 0x80, 0x10, 0xCE, 0x8A,
            0x3F, 0x76,
        ];
        fs::write(keymat_dir.join("credentials_id.bin"), cred_id_data)
            .expect("Failed to write credentials_id.bin");

        // Credential PIN binary file
        let cred_pin_data: [u8; 16] = [
            0xDB, 0x3D, 0xC7, 0x7F, 0xC2, 0x2E, 0x43, 0x00, 0x80, 0xD4, 0x1B, 0x31, 0xB6, 0xF0,
            0x48, 0x00,
        ];
        fs::write(keymat_dir.join("credentials_pin.bin"), cred_pin_data)
            .expect("Failed to write credentials_pin.bin");

        // OBK (48-byte random)
        let openssl = find_openssl_bin();
        let obk_path = keymat_dir.join("obk.bin");
        let status = Command::new(&openssl)
            .args(["rand", "-out"])
            .arg(&obk_path)
            .arg("48")
            .status()
            .expect("Failed to run openssl rand");
        assert!(status.success(), "Failed to generate obk.bin");

        // POTA P-384 key pair
        let pota_priv = keymat_dir.join("pota_private_key.der");

        // Generate EC P-384 key in PEM
        let genkey = Command::new(&openssl)
            .args(["ecparam", "-name", "secp384r1", "-genkey", "-noout"])
            .output()
            .expect("Failed to run openssl ecparam");
        assert!(
            genkey.status.success(),
            "Failed to generate POTA EC key: {}",
            String::from_utf8_lossy(&genkey.stderr)
        );

        // Convert to DER
        let mut convert = Command::new(&openssl)
            .args(["ec", "-outform", "DER", "-out"])
            .arg(&pota_priv)
            .stdin(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn openssl ec");
        convert
            .stdin
            .as_mut()
            .expect("stdin piped")
            .write_all(&genkey.stdout)
            .expect("Failed to write PEM to openssl ec stdin");
        let status = convert.wait().expect("Failed to wait for openssl ec");
        assert!(
            status.success(),
            "Failed to convert POTA private key to DER"
        );

        // Extract public key
        let pota_pub = keymat_dir.join("pota_public_key.der");
        let pubkey = Command::new(&openssl)
            .args(["ec", "-in"])
            .arg(&pota_priv)
            .args(["-inform", "DER", "-pubout", "-outform", "DER", "-out"])
            .arg(&pota_pub)
            .stderr(Stdio::null())
            .status()
            .expect("Failed to run openssl ec -pubout");
        assert!(pubkey.success(), "Failed to extract POTA public key");

        (credentials, keymat_dir)
    }

    /// Returns the resiliency storage directory inside the keymat dir.
    /// Creates a fresh directory with mode 0700 (required by the provider's
    /// resiliency init which rejects group/other permissions). Any existing
    /// directory is removed first to clear stale lock files from prior runs.
    fn get_resiliency_storage_dir(keymat_dir: &Path) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let dir = keymat_dir.join("resiliency");
        let _ = fs::remove_dir_all(&dir);
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Directory survived remove_dir_all (e.g., locked files);
                // fix permissions in place.
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
            }
            Err(e) => panic!("Failed to create resiliency storage directory: {e}"),
        }
        dir
    }

    /// Resolves the provider search path (absolute) and verifies the provider
    /// `.so` exists there.
    ///
    /// Uses `PROVIDER_PATH` if set, otherwise defaults to `target/debug` under
    /// the workspace root.  Relative paths are resolved against the workspace
    /// root to ensure correctness regardless of subprocess CWD.
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

    /// Generates an `openssl.cnf` in the key material directory.
    ///
    /// The config auto-activates the default and azihsm providers and provides
    /// absolute paths to all key material files.  This matches the documented
    /// configuration format from the provider README.
    fn generate_openssl_conf(keymat_dir: &Path, provider_path: &Path) {
        let provider_so = provider_path.join("azihsm_provider.so");
        let conf_path = keymat_dir.join("openssl.cnf");

        let content = format!(
            "\
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
azihsm = azihsm_sect

[default_sect]
activate = 1

[azihsm_sect]
module = {module}
activate = 1
azihsm-bmk-path = {dir}/bmk.bin
azihsm-muk-path = {dir}/muk.bin
azihsm-obk-path = {dir}/obk.bin
azihsm-mobk-path = {dir}/mobk.bin
azihsm-obk-source = caller
azihsm-pota-source = caller
azihsm-pota-private-key-path = {dir}/pota_private_key.der
azihsm-pota-public-key-path = {dir}/pota_public_key.der
azihsm-api-revision = 1.0
",
            module = provider_so.display(),
            dir = keymat_dir.display(),
        );

        fs::write(&conf_path, content).expect("Failed to write openssl.cnf");
    }

    /// Builds a controlled `LD_LIBRARY_PATH` for the gtest subprocess.
    ///
    /// Paths are canonicalized to absolute to ensure correctness regardless of
    /// the subprocess CWD.
    fn build_ld_library_path(provider_path: &Path) -> String {
        let mut parts: Vec<String> = Vec::new();

        // OpenSSL shared libraries — try lib64 first (RHEL/Fedora), then lib.
        if let Ok(ossl_dir) = env::var("OPENSSL_DIR") {
            let base = PathBuf::from(&ossl_dir);
            let lib64 = base.join("lib64");
            let lib = base.join("lib");
            if lib64.is_dir() {
                parts.push(
                    fs::canonicalize(&lib64)
                        .unwrap_or(lib64)
                        .to_string_lossy()
                        .into_owned(),
                );
            } else if lib.is_dir() {
                parts.push(
                    fs::canonicalize(&lib)
                        .unwrap_or(lib)
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }

        // Provider directory — contains libazihsm_api_native.so
        parts.push(
            fs::canonicalize(provider_path)
                .unwrap_or_else(|_| provider_path.to_path_buf())
                .to_string_lossy()
                .into_owned(),
        );

        parts.join(":")
    }

    /// Determines the path to the compiled C++ test binary.
    fn get_test_binary_path() -> PathBuf {
        let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
        PathBuf::from(out_dir)
            .join("build")
            .join("azihsm_ossl_cpp_tests")
    }

    /// Lists all tests available in the gtest binary.
    fn list_gtests(
        path: &Path,
        ld_library_path: &str,
        credentials: &Credentials,
        keymat_dir: &Path,
    ) -> String {
        let output = Command::new(path)
            .arg("--gtest_list_tests")
            .current_dir(keymat_dir)
            .env("OPENSSL_CONF", keymat_dir.join("openssl.cnf"))
            .env("LD_LIBRARY_PATH", ld_library_path)
            .env("AZIHSM_CREDENTIALS_ID", &credentials.id)
            .env("AZIHSM_CREDENTIALS_PIN", &credentials.pin)
            .output()
            .expect("Failed to run gtest binary for test discovery");
        assert!(
            output.status.success(),
            "gtest --gtest_list_tests failed (exit status: {}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr),
        );
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            !stdout.trim().is_empty(),
            "gtest --gtest_list_tests returned no output — binary may be broken",
        );
        stdout
    }

    /// Returns true if a discovered gtest case should be skipped because
    /// the current OpenSSL ABI cannot run it.
    ///
    /// Read from `AZIHSM_TEST_OPENSSL_MAJOR_MINOR` (set by
    /// `provider-matrix.yml` per job).  When unset, no skips happen — so a plain
    /// `cargo xtask integration-tests` run against a single OpenSSL version
    /// still runs the full suite.
    ///
    /// Convention: tag a C++ gtest case with the `_RequiresOpenssl35`
    /// suffix to mark it as 3.5-only.  When running against OpenSSL 3.0,
    /// such cases are reported as `ignored` instead of executed.
    ///
    /// Example C++ definition:
    /// ```cpp
    /// TEST(EcKeys, GenerateMlDsa_RequiresOpenssl35) { ... }
    /// ```
    fn should_skip_for_current_openssl(test_name: &str) -> bool {
        let Ok(ver) = env::var("AZIHSM_TEST_OPENSSL_MAJOR_MINOR") else {
            return false;
        };
        ver == "3.0" && test_name.ends_with("_RequiresOpenssl35")
    }

    /// Parses the gtest list output and creates test trials.
    fn parse_gtest_list(
        output: &str,
        path: PathBuf,
        ld_library_path: String,
        credentials: Credentials,
        keymat_dir: PathBuf,
        provider_path: PathBuf,
        resiliency_dir: PathBuf,
    ) -> Vec<Trial> {
        let mut tests = Vec::new();
        let mut current_suite = String::new();
        for line in output.lines() {
            if line.ends_with('.') {
                current_suite = line.trim_end_matches('.').to_string();
            } else if !line.trim().is_empty() {
                let test_name = format!("{}::{}", current_suite, line.trim());
                if should_skip_for_current_openssl(&test_name) {
                    tests.push(Trial::test(test_name, || Ok(())).with_ignored_flag(true));
                    continue;
                }
                let path = path.clone();
                let ld_path = ld_library_path.clone();
                let creds = credentials.clone();
                let km_dir = keymat_dir.clone();
                let prov_path = provider_path.clone();
                let resil_base = resiliency_dir.clone();
                tests.push(Trial::test(test_name.clone(), move || {
                    // Each test gets its own resiliency directory to avoid
                    // contention on the lock file and stale BMK/MUK state
                    // when tests run in parallel.
                    let test_resil_dir =
                        resil_base.join(test_name.replace("::", "_").replace('.', "_"));
                    let _ = fs::remove_dir_all(&test_resil_dir);
                    {
                        use std::os::unix::fs::DirBuilderExt;
                        fs::DirBuilder::new()
                            .mode(0o700)
                            .create(&test_resil_dir)
                            .expect("Failed to create per-test resiliency dir");
                    }
                    run_gtest(
                        &test_name,
                        &path,
                        &ld_path,
                        &creds,
                        &km_dir,
                        &prov_path,
                        &test_resil_dir,
                    )
                }));
            }
        }
        tests
    }

    /// Executes a single gtest test case.
    ///
    /// The subprocess runs from the key material directory with `OPENSSL_CONF`
    /// pointing to the generated config file.  The C++ test binary calls
    /// `OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG)` in `main()` to
    /// prevent OpenSSL from auto-loading the config into the default library
    /// context — each test loads it explicitly into a dedicated context.
    fn run_gtest(
        test_name: &str,
        path: &Path,
        ld_library_path: &str,
        credentials: &Credentials,
        keymat_dir: &Path,
        provider_path: &Path,
        resiliency_dir: &Path,
    ) -> Result<(), Failed> {
        let test_name = test_name.replace("::", ".");

        // Remove derived key files from previous tests.  BMK and MUK are
        // session-specific — stale files from a prior provider init cause
        // the next init to fail.
        let _ = fs::remove_file(keymat_dir.join("bmk.bin"));
        let _ = fs::remove_file(keymat_dir.join("muk.bin"));

        let mut cmd = Command::new(path);
        cmd.arg(format!("--gtest_filter={}", test_name))
            .current_dir(keymat_dir)
            .env("OPENSSL_CONF", keymat_dir.join("openssl.cnf"))
            .env("LD_LIBRARY_PATH", ld_library_path)
            .env("AZIHSM_CREDENTIALS_ID", &credentials.id)
            .env("AZIHSM_CREDENTIALS_PIN", &credentials.pin)
            .env("PROVIDER_PATH", provider_path)
            .env("AZIHSM_RESILIENCY_STORAGE_DIR", resiliency_dir);

        // Automatically enable resiliency for resiliency test suites;
        // forward the parent's value for all other tests.
        if test_name.contains("_resiliency.") {
            cmd.env("AZIHSM_RESILIENCY_ENABLED", "1");
        } else if let Ok(val) = env::var("AZIHSM_RESILIENCY_ENABLED") {
            cmd.env("AZIHSM_RESILIENCY_ENABLED", val);
        }

        let success = cmd.status().expect("Failed to run test").success();

        if success {
            Ok(())
        } else {
            Err(test_name.into())
        }
    }
}
