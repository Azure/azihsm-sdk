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

/// Test POTA endorsement signature (raw r||s, 96 bytes for ECC P-384).
///
/// This is a pre-computed ECDSA-P384 signature over an arbitrary test digest,
/// produced with the private key corresponding to `TEST_POTA_PUBLIC_KEY_DER`.
/// Used for non-TPM test environments when `AZIHSM_USE_TPM` is not set.
pub(crate) const TEST_POTA_SIGNATURE: [u8; 96] = [
    0x50, 0x83, 0x5a, 0x92, 0x51, 0xba, 0xd0, 0x08, 0x10, 0x61, 0x77, 0xef, 0x00, 0x4b, 0x09, 0x1a,
    0x1e, 0x42, 0x35, 0xcd, 0x0d, 0xa8, 0x4f, 0xff, 0x54, 0x54, 0x2b, 0x0e, 0xd7, 0x55, 0xc1, 0xd6,
    0xf2, 0x51, 0x60, 0x9d, 0x14, 0xec, 0xf1, 0x8f, 0x9e, 0x1d, 0xdf, 0xe6, 0x9b, 0x94, 0x6e, 0x32,
    0x04, 0x75, 0xf3, 0xd3, 0x0c, 0x64, 0x63, 0xb6, 0x46, 0xe8, 0xd3, 0xbf, 0x24, 0x55, 0x83, 0x03,
    0x14, 0x61, 0x1c, 0xbd, 0xe4, 0x04, 0xbe, 0x51, 0x8b, 0x14, 0x46, 0x4f, 0xdb, 0x19, 0x5f, 0xdc,
    0xc9, 0x2e, 0xb2, 0x22, 0xe6, 0x1f, 0x42, 0x6a, 0x4a, 0x59, 0x2c, 0x00, 0xa6, 0xa8, 0x97, 0x21,
];

/// Test POTA endorsement public key (DER-encoded ECC P-384, 120 bytes).
///
/// This is the SubjectPublicKeyInfo-encoded public key corresponding to the
/// private key that produced `TEST_POTA_SIGNATURE`. From NIST P-384 test vectors.
pub(crate) const TEST_POTA_PUBLIC_KEY_DER: [u8; 120] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xc2, 0xb4, 0x79, 0x44, 0xfb, 0x5d, 0xe3, 0x42,
    0xd0, 0x32, 0x85, 0x88, 0x01, 0x77, 0xca, 0x5f, 0x7d, 0x0f, 0x2f, 0xca, 0xd7, 0x67, 0x8c, 0xce,
    0x42, 0x29, 0xd6, 0xe1, 0x93, 0x2f, 0xca, 0xc1, 0x1b, 0xfc, 0x3c, 0x3e, 0x97, 0xd9, 0x42, 0xa3,
    0xc5, 0x6b, 0xf3, 0x41, 0x23, 0x01, 0x3d, 0xbf, 0x37, 0x25, 0x79, 0x06, 0xa8, 0x22, 0x38, 0x66,
    0xed, 0xa0, 0x74, 0x3c, 0x51, 0x96, 0x16, 0xa7, 0x6a, 0x75, 0x8a, 0xe5, 0x8a, 0xee, 0x81, 0xc5,
    0xfd, 0x35, 0xfb, 0xf3, 0xa8, 0x55, 0xb7, 0x75, 0x4a, 0x36, 0xd4, 0xa0, 0x67, 0x2d, 0xf9, 0x5d,
    0x6c, 0x44, 0xa8, 0x1c, 0xf7, 0x62, 0x0c, 0x2d,
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
        let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();
        let (backup_key_info, pota_endorsement) = if use_tpm {
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
            )
        } else {
            let pota_data =
                HsmPotaEndorsementData::new(&TEST_POTA_SIGNATURE, &TEST_POTA_PUBLIC_KEY_DER);
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK)),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data)),
            )
        };
        part.init(creds, None, None, backup_key_info, pota_endorsement)
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
