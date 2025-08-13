// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;

use crate::common::*;

/// Import a AES bulk key in DER encoded format to the device
///
/// # Arguments
///
/// * `dev` - Device to use for the operation.
/// * `session_id` - Session ID to use for the operation.
/// * `der` - DER encoded data to import.
/// * `key_tag` - Key tag to use when stoting the unwrapped key in the device.
///
/// # Returns
///
/// * `DdiResult<T::OpResp>` - Response of the operation.
fn der_import_aes_bulk_key(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    der: [u8; 3072],
    key_tag: u16,
) -> Result<DdiDerKeyImportCmdResp, DdiError> {
    let req = DdiDerKeyImportCmdReq {
        hdr: DdiReqHdr {
            op: DdiOp::DerKeyImport,
            sess_id: Some(session_id),
            rev: Some(DdiApiRev { major: 1, minor: 0 }),
        },
        data: DdiDerKeyImportReq {
            der: MborByteArray::new(der, 32).expect("failed to create byte array"),
            key_class: DdiKeyClass::AesBulk,
            key_tag: Some(key_tag),
            key_properties: helper_key_properties(
                DdiKeyUsage::EncryptDecrypt,
                DdiKeyAvailability::App,
            ),
        },
        ext: None,
    };
    let mut cookie = None;

    dev.exec_op(&req, &mut cookie)
}

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

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            match der_import_aes_bulk_key(dev, session_id, der, 1) {
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
                match der_import_aes_bulk_key(dev, session_id, der, key_tag) {
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

            match der_import_aes_bulk_key(dev, session_id, der, 3354) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // DerImport the key to see it completes successfully
            let resp = der_import_aes_bulk_key(dev, session_id, der, 3355);
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match der_import_aes_bulk_key(dev, session_id, der, 3356) {
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

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            match der_import_aes_bulk_key(dev, session_id, der, 1) {
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

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match der_import_aes_bulk_key(dev, session_id, der, key_tag) {
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
            match der_import_aes_bulk_key(dev, session_id, der, 3354) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let resp = der_import_aes_bulk_key(dev, session_id, der, 3355);
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match der_import_aes_bulk_key(dev, session_id, der, 3354) {
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

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            match der_import_aes_bulk_key(dev, session_id, der, 3354) {
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

            let mut der = [0u8; 3072];
            der[..buf.len()].copy_from_slice(buf);

            let mut key_tag: u16 = 0x1;

            let mut key_id = 0;
            loop {
                match der_import_aes_bulk_key(dev, session_id, der, key_tag) {
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
            match der_import_aes_bulk_key(dev, session_id, der, 3354) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            // Unwrap the key to see it completes successfully
            let resp = der_import_aes_bulk_key(dev, session_id, der, 3355);
            assert!(resp.is_ok(), "{:?}", resp);

            // Unwrap one extra key to see if it fails
            match der_import_aes_bulk_key(dev, session_id, der, 3356) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }
        },
    );
}
