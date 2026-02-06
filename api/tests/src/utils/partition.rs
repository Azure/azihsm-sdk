// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
pub(crate) const APP_ID: [u8; 16] = [1u8; 16];

/// Application PIN used for partition authentication.
///
/// This constant defines a test PIN consisting of 16 bytes, each set to
/// the value 2. Used as the credential PIN when initializing partitions
/// in test scenarios.
pub(crate) const APP_PIN: [u8; 16] = [2u8; 16];

/// Constant 48-byte owner backup key for non-TPM test environments.
/// Matches the C++ TEST_OBK in test_creds.hpp.
pub(crate) const TEST_OBK: [u8; 48] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
];

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

        //reset before init
        part.reset().expect("Partition reset failed");

        //init with test creds
        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let backup_key_info = if std::env::var("use_tpm").is_ok() {
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None)
        } else {
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK))
        };
        part.init(creds, None, None, backup_key_info)
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
