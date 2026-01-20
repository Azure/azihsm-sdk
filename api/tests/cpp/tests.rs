// Copyright (C) Microsoft Corporation. All rights reserved.

//! C++ test runner for HSM api integration tests.
//!
//! This module provides a Rust-based test harness that discovers and executes
//! C++ Google Test (gtest) tests. It uses `libtest_mimic` to integrate C++
//! tests into the Rust test infrastructure, allowing them to be run with
//! standard Rust test tools like `cargo test`.
//!
//! The runner performs the following operations:
//! - Locates the compiled C++ test binary in the build output directory
//! - Discovers available tests by parsing gtest's list output
//! - Configures library paths for dynamic linking
//! - Executes each test individually and reports results

use std::env;
use std::path::PathBuf;
use std::process::Command;

use libtest_mimic::*;

/// Entry point for the C++ test runner.
///
/// Parses command-line arguments using `libtest_mimic`, discovers all available
/// C++ tests, and executes them with the provided configuration. The process
/// exits with an appropriate status code based on test results.
fn main() {
    let args = Arguments::from_args();
    libtest_mimic::run(&args, get_tests()).exit();
}

/// Retrieves the list of all available C++ tests.
///
/// Locates the test binary, queries it for the list of available tests,
/// and creates a `Trial` for each test that can be executed by the test runner.
///
/// # Returns
///
/// A vector of `Trial` objects representing each individual test.
fn get_tests() -> Vec<Trial> {
    let test_path = get_test_binary_path();
    let test_list = list_gtests(&test_path);
    parse_gtest_list(&test_list, test_path)
}

/// Determines the path to the compiled C++ test binary.
///
/// Locates the test binary in the build output directory, which varies
/// based on the platform and build configuration. On Windows, the binary
/// is placed in either a Debug or Release subdirectory. Also configures
/// the library search path for dynamic linking.
///
/// # Returns
///
/// A `PathBuf` pointing to the test binary executable.
///
/// # Panics
///
/// Panics if the `OUT_DIR` environment variable is not set, which should
/// be provided automatically during the build process.
fn get_test_binary_path() -> PathBuf {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let mut build_dir = PathBuf::from(out_dir).join("build");

    add_to_ld_library_path(&build_dir);

    if cfg!(target_os = "windows") {
        if cfg!(debug_assertions) {
            build_dir = build_dir.join("Debug");
        } else {
            build_dir = build_dir.join("Release");
        }
    }

    build_dir.join("azihsm_api_cpp_tests")
}

/// Lists all tests available in the gtest binary.
///
/// Executes the test binary with the `--gtest_list_tests` flag to retrieve
/// a formatted list of all test suites and test cases.
///
/// # Arguments
///
/// * `path` - Path to the gtest executable
///
/// # Returns
///
/// A string containing the gtest list output in the format:
/// ```text
/// TestSuiteName.
///   test_case_1
///   test_case_2
/// ```
///
/// # Panics
///
/// Panics if the test binary cannot be executed.
fn list_gtests(path: &PathBuf) -> String {
    // unsafe {
    //     std::env::set_var("LD_LIBRARY_PATH", current_dir);
    // }

    let output = Command::new(path)
        .arg("--gtest_list_tests")
        .output()
        .expect("Failed to list tests");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Parses the gtest list output and creates test trials.
///
/// Parses the output from `gtest --gtest_list_tests` to extract test suite
/// and test case names, creating a `Trial` object for each test that can
/// be executed independently.
///
/// # Arguments
///
/// * `output` - The raw output string from `gtest --gtest_list_tests`
/// * `path` - Path to the test binary used for execution
///
/// # Returns
///
/// A vector of `Trial` objects, each representing a single test case.
fn parse_gtest_list(output: &str, path: PathBuf) -> Vec<Trial> {
    let mut tests = Vec::new();
    let mut current_suite = String::new();
    for line in output.lines().skip(1) {
        if line.ends_with('.') {
            current_suite = line.trim_end_matches('.').to_string();
        } else if !line.trim().is_empty() {
            let test_name = format!("{}::{}", current_suite, line.trim());
            let path = path.clone();
            tests.push(Trial::test(test_name.clone(), move || {
                run_gtest(&test_name, &path)
            }));
        }
    }
    tests
}

/// Executes a single gtest test case.
///
/// Runs the specified test by invoking the test binary with a filter
/// argument that selects only the target test. The test name format
/// is converted from Rust's `::` separator to gtest's `.` separator.
///
/// # Arguments
///
/// * `test_name` - The fully qualified test name in format `TestSuite::TestCase`
/// * `path` - Path to the test binary executable
///
/// # Returns
///
/// Returns `Ok(())` if the test passed, or `Err(Failed)` if the test failed.
///
/// # Panics
///
/// Panics if the test binary cannot be executed.
fn run_gtest(test_name: &str, path: &PathBuf) -> Result<(), Failed> {
    let test_name = test_name.replace("::", ".");

    let success = Command::new(path)
        .arg(format!("--gtest_filter={}", test_name))
        .status()
        .expect("Failed to run test")
        .success();

    if success {
        Ok(())
    } else {
        Err(test_name.into())
    }
}

/// Adds a directory to the system's library search path.
///
/// Updates the environment variable used for dynamic library loading to include
/// the specified directory. On Linux, this modifies `LD_LIBRARY_PATH`; on Windows,
/// it modifies `PATH`. This ensures that shared libraries built as part of the
/// project can be found at runtime.
///
/// # Arguments
///
/// * `dir` - Directory path to add to the library search path
///
/// # Safety
///
/// This function uses `env::set_var` which is inherently unsafe as it can cause
/// undefined behavior if other threads are accessing environment variables
/// concurrently. However, this is called during initialization before any tests
/// run, making it safe in this context.
#[allow(unsafe_code)]
fn add_to_ld_library_path(dir: &PathBuf) {
    let _ = dir;
    #[cfg(target_os = "linux")]
    {
        let current_ld_path = env::var("LD_LIBRARY_PATH").unwrap_or_default();
        let new_ld_path = if current_ld_path.is_empty() {
            dir.to_str().unwrap().to_string()
        } else {
            format!("{}:{}", dir.to_str().unwrap(), current_ld_path)
        };
        // SAFETY: This is safe here as it is done during initialization
        unsafe {
            env::set_var("LD_LIBRARY_PATH", new_ld_path);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let current_path = env::var("PATH").unwrap_or_default();
        let new_path = if current_path.is_empty() {
            dir.to_str().unwrap().to_string()
        } else {
            format!("{};{}", dir.to_str().unwrap(), current_path)
        };
        // SAFETY: This is safe here as it is done during initialization
        unsafe {
            env::set_var("PATH", new_path);
        }
    }
}
