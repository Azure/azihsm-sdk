// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Trybuild is not compatible with Windows CI.
#[cfg(target_os = "linux")]
#[test]
fn tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_tests/01-handler-with-self.rs");
    t.compile_fail("tests/compile_tests/02-async-handler.rs");
    t.compile_fail("tests/compile_tests/03-no-result-return.rs");
    t.compile_fail("tests/compile_tests/04-empty-impl.rs");
    t.compile_fail("tests/compile_tests/05-generic-impl.rs");
    t.compile_fail("tests/compile_tests/06-trait-impl.rs");
    t.compile_fail("tests/compile_tests/07-missing-error-attr.rs");
}
