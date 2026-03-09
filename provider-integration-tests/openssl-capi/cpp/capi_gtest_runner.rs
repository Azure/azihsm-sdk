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
        libtest_mimic::run(&args, integration::get_tests()).exit();
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

    /// Retrieves the list of all available C++ tests.
    pub fn get_tests() -> Vec<Trial> {
        let test_path = get_test_binary_path();
        let provider_path = get_provider_path();
        let ld_library_path = build_ld_library_path(&provider_path);
        let test_list = list_gtests(&test_path, &ld_library_path);
        parse_gtest_list(&test_list, test_path, provider_path, ld_library_path)
    }

    /// Resolves the provider search path (absolute) and verifies the provider
    /// `.so` exists there.
    ///
    /// Uses `PROVIDER_PATH` if set, otherwise defaults to `target/debug` under
    /// the workspace root.
    fn get_provider_path() -> PathBuf {
        let path = match env::var("PROVIDER_PATH") {
            Ok(p) if !p.is_empty() => PathBuf::from(p),
            _ => {
                let manifest_dir =
                    env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
                Path::new(&manifest_dir)
                    .ancestors()
                    .nth(2)
                    .expect("CARGO_MANIFEST_DIR does not have enough ancestors")
                    .join("target")
                    .join("debug")
            }
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

    /// Builds a controlled `LD_LIBRARY_PATH` for the gtest subprocess.
    ///
    /// The provider `.so` and its dependencies (`libazihsm_api_native.so`,
    /// `libcrypto.so.3`) need a library search path at runtime.  Cargo's
    /// `LD_LIBRARY_PATH` can contain incompatible libraries, so we build our
    /// own from:
    ///   1. The OpenSSL lib directory derived from `OPENSSL_DIR`
    ///   2. The provider directory (contains `libazihsm_api_native.so`)
    fn build_ld_library_path(provider_path: &Path) -> String {
        let mut parts: Vec<String> = Vec::new();

        // OpenSSL shared libraries — try lib64 first (RHEL/Fedora), then lib.
        if let Ok(ossl_dir) = env::var("OPENSSL_DIR") {
            let base = PathBuf::from(&ossl_dir);
            let lib64 = base.join("lib64");
            let lib = base.join("lib");
            if lib64.is_dir() {
                parts.push(lib64.to_string_lossy().into_owned());
            } else if lib.is_dir() {
                parts.push(lib.to_string_lossy().into_owned());
            }
        }

        // Provider directory — contains libazihsm_api_native.so
        parts.push(provider_path.to_string_lossy().into_owned());

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
    fn list_gtests(path: &Path, ld_library_path: &str) -> String {
        let output = Command::new(path)
            .arg("--gtest_list_tests")
            .env("LD_LIBRARY_PATH", ld_library_path)
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

    /// Parses the gtest list output and creates test trials.
    fn parse_gtest_list(
        output: &str,
        path: PathBuf,
        provider_path: PathBuf,
        ld_library_path: String,
    ) -> Vec<Trial> {
        let mut tests = Vec::new();
        let mut current_suite = String::new();
        for line in output.lines().skip(1) {
            if line.ends_with('.') {
                current_suite = line.trim_end_matches('.').to_string();
            } else if !line.trim().is_empty() {
                let test_name = format!("{}::{}", current_suite, line.trim());
                let path = path.clone();
                let provider_path = provider_path.clone();
                let ld_path = ld_library_path.clone();
                tests.push(Trial::test(test_name.clone(), move || {
                    run_gtest(&test_name, &path, &provider_path, &ld_path)
                }));
            }
        }
        tests
    }

    /// Executes a single gtest test case.
    ///
    /// A controlled `LD_LIBRARY_PATH` is set (replacing cargo's, which can
    /// contain incompatible libraries) so that the provider `.so` and its
    /// dependencies can be resolved at runtime.
    fn run_gtest(
        test_name: &str,
        path: &Path,
        provider_path: &Path,
        ld_library_path: &str,
    ) -> Result<(), Failed> {
        let test_name = test_name.replace("::", ".");

        let success = Command::new(path)
            .arg(format!("--gtest_filter={}", test_name))
            .env("PROVIDER_PATH", provider_path)
            .env("LD_LIBRARY_PATH", ld_library_path)
            .status()
            .expect("Failed to run test")
            .success();

        if success {
            Ok(())
        } else {
            Err(test_name.into())
        }
    }
}
