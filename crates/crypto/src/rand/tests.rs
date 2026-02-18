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

/// Test random vector generation functionality.
///
/// This test verifies that:
/// - The RNG can successfully generate a random vector of the requested length
/// - The returned vector has the correct length
/// - The output is not all zeros (extremely unlikely for true random data)
/// - A zero-length request returns an empty vector
#[test]
fn test_rand_vec() {
    let vec = Rng::rand_vec(1024).expect("Failed to generate random vector");
    assert_eq!(vec.len(), 1024);
    // Check that the vector is not all zeros (very unlikely for random data)
    assert_ne!(vec, vec![0u8; 1024]);

    // Zero-length should succeed and return an empty vector
    let empty = Rng::rand_vec(0).expect("Failed to generate random vector");
    assert!(empty.is_empty());
}
