// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#[test]
fn compile_tests() {
    let t = trybuild::TestCases::new();
    t.pass("tests/compile_tests/pass/*.rs");
    t.compile_fail("tests/compile_tests/fail/*.rs");
}
