// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azihsm_crypto::pem_to_der;

use super::*;
use crate::utils::partition::*;

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
        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);
        let use_tpm = std::env::var("AZIHSM_USE_TPM").is_ok();
        let pota_result = if use_tpm {
            None
        } else {
            Some(generate_pota_endorsement(&part))
        };
        let (obk_info, pota_endorsement) = if use_tpm {
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, None),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Tpm, None),
            )
        } else {
            let (pota_sig, pota_pub_key_der) = pota_result.as_ref().unwrap();
            let pota_data = HsmPotaEndorsementData::new(pota_sig, pota_pub_key_der);
            (
                HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK)),
                HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data)),
            )
        };
        part.init(creds, None, None, obk_info, pota_endorsement)
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Caller source with no OBK should fail
        let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, None);

        // Provide a valid POTA endorsement so the failure is attributable to OBK
        let (pota_sig, pota_pub_key_der) = generate_pota_endorsement(&part);
        let pota_data = HsmPotaEndorsementData::new(&pota_sig, &pota_pub_key_der);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
        assert!(result.is_err(), "Init with null OBK should fail");
        assert_eq!(
            result.unwrap_err(),
            HsmError::InvalidArgument,
            "Expected InvalidArgument error"
        );
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Caller source with empty OBK should fail
        let empty_obk: [u8; 0] = [];
        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&empty_obk));

        // Provide a valid POTA endorsement so the failure is attributable to OBK
        let (pota_sig, pota_pub_key_der) = generate_pota_endorsement(&part);
        let pota_data = HsmPotaEndorsementData::new(&pota_sig, &pota_pub_key_der);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // TPM source ignores the caller-provided OBK at the Rust API level and
        // attempts TPM operations, which fail without TPM hardware (e.g., in simulator).
        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Tpm, Some(&TEST_OBK));

        // Provide a valid POTA endorsement so the failure is attributable to OBK
        let (pota_sig, pota_pub_key_der) = generate_pota_endorsement(&part);
        let pota_data = HsmPotaEndorsementData::new(&pota_sig, &pota_pub_key_der);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Invalid OBK source value should fail
        let obk_config = HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource(99), Some(&TEST_OBK));

        // Provide a valid POTA endorsement so the failure is attributable to OBK
        let (pota_sig, pota_pub_key_der) = generate_pota_endorsement(&part);
        let pota_data = HsmPotaEndorsementData::new(&pota_sig, &pota_pub_key_der);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
        assert!(result.is_err(), "Init with invalid OBK source should fail");
        assert_eq!(
            result.unwrap_err(),
            HsmError::InvalidArgument,
            "Expected InvalidArgument error"
        );
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Provide a valid OBK config so the failure is attributable to POTA endorsement
        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK));

        // Caller source with empty endorsement buffers should fail
        let empty_sig: [u8; 0] = [];
        let empty_pubkey: [u8; 0] = [];
        let pota_data = HsmPotaEndorsementData::new(&empty_sig, &empty_pubkey);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Provide a valid OBK config so the failure is attributable to POTA endorsement
        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK));

        // Caller source with no endorsement data should fail
        let pota_endorsement = HsmPotaEndorsement::new(HsmPotaEndorsementSource::Caller, None);

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
        assert!(result.is_err(), "Init with null endorsement should fail");
        assert_eq!(
            result.unwrap_err(),
            HsmError::InvalidArgument,
            "Expected InvalidArgument error"
        );
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

        let creds = HsmCredentials::new(&APP_ID, &APP_PIN);

        // Provide a valid OBK config so the failure is attributable to POTA endorsement
        let obk_config =
            HsmOwnerBackupKeyConfig::new(HsmOwnerBackupKeySource::Caller, Some(&TEST_OBK));

        // Invalid source value should fail
        let signature_data = [0u8; 96];
        let public_key_data = [0u8; 97];
        let pota_data = HsmPotaEndorsementData::new(&signature_data, &public_key_data);
        let pota_endorsement =
            HsmPotaEndorsement::new(HsmPotaEndorsementSource(99), Some(pota_data));

        let result = part.init(creds, None, None, obk_config, pota_endorsement);
        assert!(result.is_err(), "Init with invalid POTA source should fail");
        assert_eq!(
            result.unwrap_err(),
            HsmError::InvalidArgument,
            "Expected InvalidArgument error"
        );
    }
}
