// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use mcr_ddi::*;
use mcr_ddi_types::*;

use crate::common::*;

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                1,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match helper_der_import_aes_bulk_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_tag,
                    DdiKeyClass::AesGcmBulkUnapproved,
                    buf,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                        println!("Firmware is not built with mcr_test_hooks.");
                        return;
                    }
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3354,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // DerImport the key to see it completes successfully
            let resp = helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3355,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            );

            if let Err(err) = &resp {
                if firmware_not_built_with_test_hooks(err) {
                    println!("Firmware is not built with mcr_test_hooks.");
                    return;
                }
            }

            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3356,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error_after_dma_out() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                1,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error_after_dma_out_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match helper_der_import_aes_bulk_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_tag,
                    DdiKeyClass::AesGcmBulkUnapproved,
                    buf,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                        println!("Firmware is not built with mcr_test_hooks.");
                        return;
                    }
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // DerImport the key with test action set to fail and see it fails
            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3354,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let resp = helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3355,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            );

            if let Err(err) = &resp {
                if firmware_not_built_with_test_hooks(err) {
                    println!("Firmware is not built with mcr_test_hooks.");
                    return;
                }
            }

            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3354,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error_after_dma_end() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3354,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}

#[test]
fn test_der_import_aes_bulk_key_with_rollback_error_after_dma_end_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            // generate AES 256 bulk key; 32 bytes of random data
            let mut buf = [0u8; 32];
            let buf = &mut buf;
            let _ = rand_bytes(buf);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match helper_der_import_aes_bulk_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_tag,
                    DdiKeyClass::AesGcmBulkUnapproved,
                    buf,
                ) {
                    Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                        println!("Firmware is not built with mcr_test_hooks.");
                        return;
                    }
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => key_id = val.data.key_id,
                }

                key_tag += 1;
            }

            // Delete Key
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            // Unwrap the key with test action set to fail and see it fails
            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3354,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let resp = helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3355,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            );

            if let Err(err) = &resp {
                if firmware_not_built_with_test_hooks(err) {
                    println!("Firmware is not built with mcr_test_hooks.");
                    return;
                }
            }

            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match helper_der_import_aes_bulk_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                3356,
                DdiKeyClass::AesGcmBulkUnapproved,
                buf,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd)) => {
                    println!("Firmware is not built with mcr_test_hooks.")
                }
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}
