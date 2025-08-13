// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_aes_generate_malformed_ddi() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Make the header have the opcode but body of different type
            {
                let resp = helper_get_api_rev_op(
                    dev,
                    DdiOp::AesGenerateKey,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::DdiDecodeFailed)
                ));
            }

            {
                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::AesGenerateKey,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: 0x1,
                        y: MborByteArray::from_slice(&[0x1; 32])
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::DdiDecodeFailed)
                ));
            }
        },
    );
}

#[test]
fn test_aes_generate_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_aes_generate_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(20),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_aes_generate_invalid_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_aes_generate_session_only_key_with_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(0x9876),
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_aes_generate_session_only_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_aes_generate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_error() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let mut key_tag: u16 = 0x1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
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

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerIoFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3356)) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_error_after_dma_out() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_error_after_dma_out_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let mut key_tag = 1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
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

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaOutFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3356)) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_error_after_dma_end() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}

#[test]
fn test_aes_bulk_generate_with_rollback_error_after_dma_end_after_exhaust_keys() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let mut key_tag = 0x1;
            let mut key_id = 0;
            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
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

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);

            if !set_test_action(ddi, path, DdiTestAction::TriggerDmaEndFailure) {
                println!("Firmware is not built with test_action test_hooks.");
                return;
            }

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();
            let app_sess_id = resp.data.sess_id;

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3354)) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match generate_aes_bulk_256_key(dev, &app_sess_id, Some(3356)) {
                Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = helper_close_session(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "{:?}", resp);
        },
    );
}
