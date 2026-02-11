// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Partition management utilities for HSM testing.
//!
//! This module provides helper functions for creating and managing HSM partitions
//! in test scenarios. It handles partition discovery, opening, initialization,
//! and cleanup operations.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use azihsm_crypto::*;
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

/// Test POTA endorsement private key (DER-encoded ECC P-384, 185 bytes).
/// This is the same key used by DDI integration tests (TEST_POTA_ECC_PRIVATE_KEY).
const TEST_POTA_PRIVATE_KEY: [u8; 185] = [
    0x30, 0x81, 0xb6, 0x02, 0x01, 0x00, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x04, 0x81, 0x9e, 0x30, 0x81, 0x9b, 0x02, 0x01,
    0x01, 0x04, 0x30, 0x17, 0xe9, 0x1c, 0xac, 0xf7, 0xb7, 0x21, 0xd7, 0x75, 0x20, 0x02, 0x07, 0xbc,
    0xaa, 0x94, 0x2c, 0xe3, 0xb5, 0x5b, 0x78, 0x13, 0xcc, 0x8b, 0xde, 0x87, 0x65, 0x6b, 0xe1, 0x7b,
    0xc2, 0xa8, 0xcc, 0x89, 0x33, 0x4e, 0xcd, 0xaa, 0x9d, 0x1d, 0x09, 0xf1, 0xc7, 0x01, 0x1b, 0x64,
    0xeb, 0x78, 0x5b, 0xa1, 0x64, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67,
    0xc2, 0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20,
    0xce, 0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90,
    0xab, 0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99,
    0xc8, 0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a,
    0xee, 0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02,
    0x7d, 0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
];

/// Test POTA endorsement public key (DER-encoded ECC P-384, 120 bytes).
/// Corresponds to TEST_POTA_PRIVATE_KEY above.
const TEST_POTA_PUBLIC_KEY_DER: [u8; 120] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x42, 0x0d, 0x73, 0xeb, 0xf0, 0x67, 0xc2,
    0xf9, 0x77, 0xbd, 0x51, 0xab, 0xfb, 0xe1, 0xf6, 0x53, 0x19, 0xb7, 0x57, 0xe0, 0xa9, 0x20, 0xce,
    0x4f, 0x21, 0xbb, 0xd4, 0xa7, 0x84, 0x1c, 0x93, 0x45, 0xf1, 0xea, 0xd9, 0x5f, 0xe5, 0x90, 0xab,
    0x57, 0xe1, 0xea, 0xfc, 0xd2, 0x06, 0xef, 0x21, 0xa2, 0xad, 0x10, 0xd3, 0x17, 0x6e, 0x99, 0xc8,
    0x22, 0x26, 0x23, 0x08, 0x57, 0xa7, 0x56, 0x08, 0x45, 0xe3, 0xda, 0x12, 0xc7, 0xdc, 0x3a, 0xee,
    0x01, 0xfc, 0x37, 0xab, 0x1c, 0x8d, 0xc6, 0xd0, 0x64, 0x7a, 0x7d, 0xc2, 0x67, 0xfc, 0x02, 0x7d,
    0x8d, 0xa3, 0xc8, 0x01, 0x4b, 0xa4, 0x0d, 0x98,
];

/// Dynamically generates a POTA endorsement (signature + public key DER) for a partition.
///
/// This function:
/// 1. Retrieves the PID public key from the partition
/// 2. Parses the DER-encoded public key to extract x,y coordinates
/// 3. Builds the uncompressed point format (0x04 || x || y)
/// 4. Loads the hardcoded ECC P-384 private key from DER
/// 5. Signs the uncompressed point with ECDSA-SHA384 (which internally
///    hashes the data with SHA-384 before signing)
/// 6. Returns the hardcoded public key DER
///
/// On Linux this uses OpenSSL; on Windows it uses CNG/SymCrypt, via the
/// platform-abstracted `azihsm_crypto` crate.
///
/// # Returns
///
/// A tuple of (raw_signature, public_key_der) suitable for use as
/// `HsmPotaEndorsementData`.
///
/// # Panics
///
/// Panics if any cryptographic operation fails.
#[allow(clippy::expect_used)]
pub(crate) fn generate_pota_endorsement(part: &HsmPartition) -> (Vec<u8>, Vec<u8>) {
    // Get PID public key DER from partition
    let pid_pub_key_der = part.pub_key().expect("Failed to get PID public key");

    // Parse DER to get x,y coordinates
    let pid_pub_key_obj =
        DerEccPublicKey::from_der(&pid_pub_key_der).expect("Failed to parse PID public key DER");

    // Build uncompressed point: 0x04 || x || y
    let mut uncompressed_point = vec![0x04u8];
    uncompressed_point.extend_from_slice(pid_pub_key_obj.x());
    uncompressed_point.extend_from_slice(pid_pub_key_obj.y());

    // Load hardcoded ECC P-384 private key from DER
    let priv_key = EccPrivateKey::from_bytes(&TEST_POTA_PRIVATE_KEY)
        .expect("Failed to load hardcoded ECC P-384 private key");

    // Sign the uncompressed point with ECDSA-SHA384
    // EcdsaAlgo internally hashes data with SHA-384 then signs the hash
    let hash_algo = HashAlgo::sha384();
    let mut ecdsa_algo = EcdsaAlgo::new(hash_algo);
    let signature = Signer::sign_vec(&mut ecdsa_algo, &priv_key, &uncompressed_point)
        .expect("Failed to sign PID public key hash");

    // Return hardcoded public key DER (SubjectPublicKeyInfo)
    (signature, TEST_POTA_PUBLIC_KEY_DER.to_vec())
}

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
            .expect("Failed to open the partition");

        //reset before init
        part.reset().expect("Partition reset failed");

        //init with test creds
        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let rev = HsmApiRev { major: 1, minor: 0 };
        let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();

        let pota_owned = if !use_tpm {
            Some(generate_pota_endorsement(&part))
        } else {
            None
        };

        let (backup_key_info, pota_endorsement) = if use_tpm {
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
            )
        } else {
            let (ref pota_sig, ref pota_pub_key_der) = *pota_owned.as_ref().unwrap();
            let pota_data = HsmPotaEndorsementData::new(pota_sig, pota_pub_key_der);
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK)),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data)),
            )
        };
        part.init(rev, creds, None, None, backup_key_info, pota_endorsement)
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
