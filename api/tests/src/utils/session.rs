// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Session management utilities for HSM testing.
//!
//! This module provides helper functions for creating and managing HSM sessions
//! in test scenarios. It handles partition discovery, opening, initialization,
//! session creation, and cleanup operations.

use azihsm_api::*;
use azihsm_api_tests_macro::*;
use tracing::*;

use crate::utils::partition::*;

/// Executes a test function with an initialized HSM session.
///
/// This utility function discovers available HSM partitions, opens each one,
/// initializes it with test credentials, creates a session with the maximum
/// supported API revision, and executes the provided test closure with the
/// session as a parameter. This allows tests to run against sessions on all
/// available partitions sequentially.
///
/// # Type Parameters
///
/// * `F` - A closure that accepts an `HsmSession`
///
/// # Panics
///
/// Panics if:
/// - No partitions are found in the system
/// - A partition fails to open
/// - Partition initialization fails
/// - Session creation fails
#[allow(unused)]
#[allow(clippy::expect_used)]
pub(crate) fn with_session<F>(mut test: F)
where
    F: FnMut(HsmSession),
{
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");

        //reset before init
        part.reset().expect("Partition reset failed");

        //init with test creds
        let creds = HsmCredentials::new(&[1u8; 16], &[2u8; 16]);
        let rev = TEST_API_REV;
        let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();

        let pota_data = if !use_tpm {
            Some(generate_pota_endorsement(&part))
        } else {
            None
        };

        let (obk_info, pota_endorsement) = if use_tpm {
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
            )
        } else {
            let (ref pota_sig, ref pota_pub_key_der) = *pota_data.as_ref().unwrap();
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK)),
                HsmPotaEndorsement::new(
                    HsmPotaEndorsementSource::Caller,
                    Some(HsmPotaEndorsementData::new(pota_sig, pota_pub_key_der)),
                ),
            )
        };
        part.init(rev, creds, None, None, obk_info, pota_endorsement)
            .expect("Partition init failed");
        let mut session = part
            .open_session(rev, &creds, None)
            .expect("Failed to open session");
        test(session);
    }
}

#[session_test]
fn test_with_session(session: HsmSession) {
    info!("Testing with session: {:?}", session.id());
}
