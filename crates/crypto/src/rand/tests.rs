// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

/// Test basic random byte generation functionality.
///
/// This test verifies that:
/// - The RNG can successfully generate random bytes
/// - The output is not all zeros (extremely unlikely for true random data)
/// - No errors occur during normal operation
#[test]
fn test_rand_bytes() {
    let mut buf = [0u8; 1024];
    assert!(Rng::rand_bytes(&mut buf).is_ok());
    // Check that the buffer is not all zeros (very unlikely for random data)
    assert_ne!(buf, [0u8; 1024]);
}
