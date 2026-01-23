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

        // Test retrieving cert chain size (slot 0)
        let cert_size = part
            .cert_chain(0, None)
            .expect("Failed to get cert chain size");

        // Test retrieving cert chain using cert_chain_vec
        let cert_chain_vec = part
            .cert_chain_vec(0)
            .expect("Failed to retrieve cert chain");
        assert_eq!(cert_chain_vec.len(), cert_size, "Cert chain size mismatch");

        // Test retrieving cert chain with buffer
        let mut cert_buffer = vec![0u8; cert_size];
        let actual_size = part
            .cert_chain(0, Some(&mut cert_buffer[..]))
            .expect("Failed to retrieve cert chain with buffer");
        assert_eq!(
            actual_size, cert_size,
            "Retrieved cert chain size doesn't match expected size"
        );
        assert_eq!(
            cert_buffer[..actual_size],
            cert_chain_vec[..],
            "Cert chain content mismatch"
        );
    }
}
