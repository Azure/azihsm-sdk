// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::pem_to_der;

use super::*;
use crate::utils::partition::*;

/// Builds a valid caller-source OBK config using the test OBK.
fn make_valid_obk() -> HsmOwnerBackupKeyConfig<'static> {
    HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK))
}

/// Generates valid POTA endorsement buffers (signature, public key DER) for
/// the given partition. Callers use these owned buffers to construct an
/// `HsmPotaEndorsementData` that borrows them, so the buffers must outlive
/// the endorsement.
fn make_valid_pota_parts(part: &HsmPartition) -> (Vec<u8>, Vec<u8>) {
    generate_pota_endorsement(part)
}

#[api_test]
fn test_partition_info_list() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
}

#[api_test]
fn test_open_partition() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
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
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();

        let pota_data = if !use_tpm {
            Some(make_valid_pota_parts(&part))
        } else {
            None
        };

        let (obk_info, pota_endorsement) = if use_tpm {
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
            )
        } else {
            let (ref sig, ref pubkey) = *pota_data.as_ref().unwrap();
            (
                make_valid_obk(),
                HsmPotaEndorsement::new(
                    HsmPotaEndorsementSource::Caller,
                    Some(HsmPotaEndorsementData::new(sig, pubkey)),
                ),
            )
        };
        part.init(
            HsmApiRev { major: 1, minor: 0 },
            creds,
            None,
            None,
            obk_info,
            pota_endorsement,
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

#[api_test]
fn test_init_caller_source_with_null_obk_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, None);
        let (sig, pubkey) = make_valid_pota_parts(&part);
        let pota_data = HsmPotaEndorsementData::new(&sig, &pubkey);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert_eq!(result.unwrap_err(), HsmError::InvalidArgument);
    }
}

#[api_test]
fn test_init_caller_source_with_empty_obk_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&[]));
        let (sig, pubkey) = make_valid_pota_parts(&part);
        let pota_data = HsmPotaEndorsementData::new(&sig, &pubkey);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert!(result.is_err(), "Init with empty OBK should fail");
    }
}

#[api_test]
fn test_init_tpm_obk_source_with_obk_provided_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, Some(&TEST_OBK));
        let (sig, pubkey) = make_valid_pota_parts(&part);
        let pota_data = HsmPotaEndorsementData::new(&sig, &pubkey);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert!(
            result.is_err(),
            "Init with TPM OBK source and caller-provided OBK should fail"
        );
    }
}

#[api_test]
fn test_init_invalid_obk_source_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource(99), Some(&TEST_OBK));
        let (sig, pubkey) = make_valid_pota_parts(&part);
        let pota_data = HsmPotaEndorsementData::new(&sig, &pubkey);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert_eq!(result.unwrap_err(), HsmError::InvalidArgument);
    }
}

#[api_test]
fn test_init_caller_source_with_empty_endorsement_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = make_valid_obk();
        let pota_data = HsmPotaEndorsementData::new(&[], &[]);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert!(result.is_err(), "Init with empty endorsement should fail");
    }
}

#[api_test]
fn test_init_caller_source_with_null_endorsement_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = make_valid_obk();
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, None);

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert_eq!(result.unwrap_err(), HsmError::InvalidArgument);
    }
}

#[api_test]
fn test_init_invalid_pota_source_fails() {
    let part_mgr = HsmPartitionManager::partition_info_list();
    assert!(!part_mgr.is_empty(), "No partitions found.");
    for part_info in part_mgr.iter() {
        let part = HsmPartitionManager::open_partition(&part_info.path)
            .expect("Failed to open the partition");
        part.reset().expect("Partition reset failed");

        let obk_config = make_valid_obk();
        let pota_data = HsmPotaEndorsementData::new(&[0u8; 96], &[0u8; 97]);
        let pota = HsmPotaEndorsement::new(HsmPotaEndorsementSource(99), Some(pota_data));

        let result = part.init(
            HsmApiRev { major: 1, minor: 0 },
            HsmCredentials::new(&APP_ID, &APP_PIN),
            None,
            None,
            obk_config,
            pota,
        );
        assert_eq!(result.unwrap_err(), HsmError::InvalidArgument);
    }
}
