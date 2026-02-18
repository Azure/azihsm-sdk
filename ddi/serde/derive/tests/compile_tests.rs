// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Why are these tests only running on Linux?
// ==========================================
// These trybuild tests are currently configured to only run on Linux. We have
// disabled running these on Windows due to an intermittent Windows-specific
// OneBranch pipeline issue whose fix interferes with these tests running on
// OneBranch Windows containers.
//
// The intermittent OneBranch issue creates occasional `STATUS_ACCESS_VIOLATION`
// runtime errors when attempting to build and run Rust code with Cargo on
// Windows containers. A workaround for this issue is to set the
// `CARGO_TARGET_DIR` environment variable to a location outside of the
// host-mounted directory within the container (somewhere like
// `C:\cargo_target_dir`). This changes where Cargo/rustc stores build artifacts
// and avoids the runtime errors. By fixing this issue, we are fixing a
// stability problem in our CI/CD pipelines.
//
// However, this fix contradicts with a known issue in trybuild where resources
// and dependencies cannot be accessed outside of the Cargo target directory.
// See these links for more information:
//
// * https://github.com/dtolnay/trybuild/issues/296
// * https://github.com/dtolnay/trybuild/pull/303
// * https://github.com/dtolnay/trybuild/issues/261
//
// Disabling these on Windows should not hurt our code quality; because these
// are simple rustc compilation checks, the Rust Compiler should produce the
// same test results on both Linux and Windows. So, by running these only on
// Linux, we aren't missing anything crucial.

#[cfg(target_os = "linux")]
#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_tests/01-union.rs");
    t.compile_fail("tests/compile_tests/02-struct-invalid.rs");
    t.compile_fail("tests/compile_tests/03-enum-invalid.rs");
}
