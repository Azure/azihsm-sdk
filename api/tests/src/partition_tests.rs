// Copyright (C) Microsoft Corporation. All rights reserved.

use super::*;

#[api_test]
fn test_parittion_info_list() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
}

#[api_test]
fn test_open_partition() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        assert_eq!(part.info().path, part_info.path);
    }
}

#[api_test]
fn test_paritition_info() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        assert_eq!(part.info().path, part_info.path);
        assert!(
            part.api_rev_range().min() <= part.api_rev_range().max(),
            "Invalid API revision range"
        );
    }
}

#[api_test]
fn test_parition_init() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        let creds = HsmCredentials::new(&[1u8; 16], &[2u8; 16]);
        part.init(creds, None, None, None)
            .expect("Partition init failed");
    }
}

#[api_test]
fn test_cert_chain() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");

        let cert_chain = part.cert_chain(0).expect("Failed to retrieve cert chain");
        assert!(!cert_chain.is_empty(), "Cert chain is empty");
        assert!(
            cert_chain.contains("-----BEGIN CERTIFICATE-----"),
            "Cert chain missing PEM header"
        );
    }
}
