// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host tests for the helpers that need no PAL.

use super::*;

#[test]
fn ct_eq_compares_whole_strings() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}
