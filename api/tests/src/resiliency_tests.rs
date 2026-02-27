// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resiliency integration tests.
//!
//! Verifies that a partition can be initialized with a resiliency config,
//! then reset and re-initialized — exercising the lock guard, storage
//! read/write, and retry machinery.

use super::*;
use crate::utils::partition::*;
use crate::utils::resiliency::make_resiliency_config;
use crate::utils::resiliency::make_resiliency_config_in;

/// Opens a partition, resets it, initialises with a resiliency config,
/// then resets and re-initialises a second time.
///
/// The second init simulates the post-migration / crash-recovery path
/// where the resiliency storage already contains a cached BMK from the
/// first init.
#[api_test]
fn test_init_reset_init_with_resiliency() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");

    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");

        // First cycle: reset → init with resiliency
        part.reset().expect("First reset failed");

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let (obk_info, pota_endorsement) = make_init_params(&part);

        let (resiliency_config, _ctx) = make_resiliency_config(&part);
        part.init(
            creds,
            None,
            None,
            obk_info,
            pota_endorsement,
            Some(resiliency_config),
        )
        .expect("First init with resiliency config failed");

        let bmk_first = part.bmk_vec();
        assert!(
            !bmk_first.is_empty(),
            "BMK should be non-empty after first init"
        );

        // Second cycle: reset → re-init with resiliency
        // The resiliency storage now has a cached BMK from the first init.
        part.reset().expect("Second reset failed");

        let (obk_info2, pota_endorsement2) = make_init_params(&part);

        let resiliency_config2 = make_resiliency_config_in(_ctx.dir(), &part);
        part.init(
            creds,
            None,
            None,
            obk_info2,
            pota_endorsement2,
            Some(resiliency_config2),
        )
        .expect("Second init with resiliency config failed");

        let bmk_second = part.bmk_vec();
        assert_eq!(
            bmk_first, bmk_second,
            "BMK from second init (restored from resiliency storage) must match the first"
        );
    }
}
