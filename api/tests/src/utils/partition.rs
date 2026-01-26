// Copyright (C) Microsoft Corporation. All rights reserved.

//! Partition management utilities for HSM testing.
//!
//! This module provides helper functions for creating and managing HSM partitions
//! in test scenarios. It handles partition discovery, opening, initialization,
//! and cleanup operations.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use tracing::*;

/// Application identifier used for partition authentication.
///
/// This constant defines a test application ID consisting of 16 bytes,
/// each set to the value 1. Used as the credential identifier when
/// initializing partitions in test scenarios.
const APP_ID: [u8; 16] = [1u8; 16];

/// Application PIN used for partition authentication.
///
/// This constant defines a test PIN consisting of 16 bytes, each set to
/// the value 2. Used as the credential PIN when initializing partitions
/// in test scenarios.
const APP_PIN: [u8; 16] = [2u8; 16];

/// Executes a test function with an initialized HSM partition.
///
/// This utility function discovers available HSM partitions, opens each one,
/// initializes it with test credentials, and executes the provided test closure
/// with the partition and credentials as parameters. This allows tests to run
/// against all available partitions sequentially.
///
/// # Type Parameters
///
/// * `F` - A closure that accepts an `HsmPartition` and `HsmCredentials`
///
/// # Panics
///
/// Panics if:
/// - No partitions are found in the system
/// - A partition fails to open
/// - Partition initialization fails
#[allow(unused)]
#[allow(clippy::expect_used)]
pub(crate) fn with_partition<F>(mut test: F)
where
    F: FnMut(HsmPartition, HsmCredentials),
{
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let rev = part.api_rev_range().max();
        part.init(creds, None, None, None)
            .expect("Partition init failed");
        test(part, creds);
    }
}

#[partition_test]
fn test_with_partition(partition: HsmPartition, creds: HsmCredentials) {
    assert_eq!(creds.id(), &APP_ID, "Invalid credentials ID");
    assert_eq!(creds.pin(), &APP_PIN, "Invalid credentials key");
    info!("Testing with partition: {:?}", partition.path());
}
