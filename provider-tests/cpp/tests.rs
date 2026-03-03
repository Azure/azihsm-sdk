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

#![cfg(feature = "integration")]
#![allow(clippy::unwrap_used)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use libtest_mimic::*;

/// Entry point for the C++ test runner.
///
/// Parses command-line arguments using `libtest_mimic`, discovers all available
/// C++ tests, and executes them with the provided configuration.
fn main() {
    let args = Arguments::from_args();
    libtest_mimic::run(&args, get_tests()).exit();
}

/// Retrieves the list of all available C++ tests.
fn get_tests() -> Vec<Trial> {
    let test_path = get_test_binary_path();
    let provider_path = get_provider_path();
    let test_list = list_gtests(&test_path);
    parse_gtest_list(&test_list, test_path, provider_path)
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
                .parent()
                .expect("CARGO_MANIFEST_DIR has no parent")
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

/// Determines the path to the compiled C++ test binary.
fn get_test_binary_path() -> PathBuf {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    PathBuf::from(out_dir).join("build").join("azihsm_ossl_cpp_tests")
}

/// Lists all tests available in the gtest binary.
fn list_gtests(path: &Path) -> String {
    let output = Command::new(path)
        .arg("--gtest_list_tests")
        .env_remove("LD_LIBRARY_PATH")
        .output()
        .expect("Failed to list tests");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Parses the gtest list output and creates test trials.
fn parse_gtest_list(output: &str, path: PathBuf, provider_path: PathBuf) -> Vec<Trial> {
    let mut tests = Vec::new();
    let mut current_suite = String::new();
    for line in output.lines().skip(1) {
        if line.ends_with('.') {
            current_suite = line.trim_end_matches('.').to_string();
        } else if !line.trim().is_empty() {
            let test_name = format!("{}::{}", current_suite, line.trim());
            let path = path.clone();
            let provider_path = provider_path.clone();
            tests.push(Trial::test(test_name.clone(), move || {
                run_gtest(&test_name, &path, &provider_path)
            }));
        }
    }
    tests
}

/// Executes a single gtest test case.
///
/// `LD_LIBRARY_PATH` is removed so that the dynamic linker uses the RUNPATH
/// entries baked into the gtest binary and the provider `.so` rather than
/// cargo's library search path, which can contain incompatible libraries.
fn run_gtest(test_name: &str, path: &Path, provider_path: &Path) -> Result<(), Failed> {
    let test_name = test_name.replace("::", ".");

    let success = Command::new(path)
        .arg(format!("--gtest_filter={}", test_name))
        .env("PROVIDER_PATH", provider_path)
        .env_remove("LD_LIBRARY_PATH")
        .status()
        .expect("Failed to run test")
        .success();

    if success {
        Ok(())
    } else {
        Err(test_name.into())
    }
}
