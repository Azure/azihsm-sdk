// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::pem_to_der;

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
        assert_eq!(part.path(), part_info.path);
    }
}

#[api_test]
fn test_partition_properties() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");

    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");

        // Test path getter
        let path = part.path();
        assert_eq!(path, part_info.path, "Path should match partition info");

        // Test type getter
        let part_type = part.part_type();
        assert!(
            matches!(part_type, HsmPartType::Virtual | HsmPartType::Physical),
            "Partition type should be Virtual or Physical"
        );

        // Test driver_ver getter
        let driver_ver = part.driver_ver();
        assert!(!driver_ver.is_empty(), "Driver version should not be empty");

        // Test firmware_ver getter
        let firmware_ver = part.firmware_ver();
        assert!(
            !firmware_ver.is_empty(),
            "Firmware version should not be empty"
        );

        // Test hardware_ver getter
        let hardware_ver = part.hardware_ver();
        assert!(
            !hardware_ver.is_empty(),
            "Hardware version should not be empty"
        );

        // Test pci_info getter
        let pci_info = part.pci_info();
        assert!(!pci_info.is_empty(), "PCI info should not be empty");
    }
}

#[api_test]
fn test_partition_init() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        //reset before init
        part.reset().expect("Partition reset failed");
        //init with dummy creds
        let creds = HsmCredentials::new(&[1u8; 16], &[2u8; 16]);
        part.init(creds, None, None, None, HsmOwnerBackupKeySource::Random)
            .expect("Partition init failed");
    }
}

#[api_test]
fn test_partition_init_caller_obk() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the parition");
        let creds = HsmCredentials::new(&[1u8; 16], &[2u8; 16]);
        let obk = [0x2Au8; 48];
        part.init(
            creds,
            None,
            None,
            Some(&obk),
            HsmOwnerBackupKeySource::Caller,
        )
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

        let blocks: Vec<String> = cert_chain
            .split("-----BEGIN CERTIFICATE-----")
            .filter(|part| part.contains("-----END CERTIFICATE-----"))
            .filter_map(|part| {
                part.split("-----END CERTIFICATE-----")
                    .next()
                    .map(|content| {
                        format!(
                            "-----BEGIN CERTIFICATE-----{}-----END CERTIFICATE-----",
                            content
                        )
                    })
            })
            .collect();
        assert!(!blocks.is_empty(), "Parsed cert chain is empty");
        for block in blocks {
            pem_to_der(block.as_bytes()).expect("Failed to parse certificate PEM");
        }
    }
}
