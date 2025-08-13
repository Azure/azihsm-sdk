// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::cmp::min;
use std::thread;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;

use crate::common::*;

const RAW_MSG: [u8; 512] = [1u8; 512];

#[test]
fn test_masked_key_aes_128_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes128);
        },
    );
}

#[test]
fn test_masked_key_aes_192_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes192);
        },
    );
}

#[test]
fn test_masked_key_aes_256_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            test_masked_key_aes_gen(dev, session_id, DdiAesKeySize::Aes256);
        },
    );
}

#[test]
fn test_masked_key_aes_bulk_256_gen() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) == DdiDeviceKind::Virtual {
                tracing::debug!(
                    "Masked key test is only support in Physical platform. Skipping the test..."
                );
                return;
            }

            let max_keys = get_device_info(ddi, path).tables as usize * 7;
            // We open a session in each thread and we can only do MAX_SESSIONS sessions max.
            let max_threads = MAX_SESSIONS;
            let thread_count = min(max_keys, max_threads);
            let thread_device_path = path.to_string();
            let mut parent_dev = dev.clone();

            let thread = thread::spawn(move || {
                test_masked_key_aes_gcm_encrypt_decrypt_thread_fn(
                    thread_device_path,
                    thread_count,
                    &mut parent_dev,
                    session_id,
                );
            });
            thread.join().unwrap();
        },
    );
}

#[test]
fn test_masked_key_aes_bulk_gen_with_rollback_error() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = generate_aes_bulk_256_key(dev, &session_id, Some(1));
            assert!(resp.is_ok(), "{:?}", resp);
            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;

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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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
fn test_masked_key_aes_bulk_gen_with_rollback_after_exhaust_keys() {
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
            let mut masked_key =
                MborByteArray::from_slice(&[]).expect("Failed to create temp array");
            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => {
                        masked_key = val.data.masked_key;
                        key_id = val.data.key_id;
                    }
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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
                Err(DdiError::DdiStatus(DdiStatus::InvalidKeyType)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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
fn test_masked_key_aes_bulk_gen_with_rollback_error_after_dma_out() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = generate_aes_bulk_256_key(dev, &session_id, Some(1));
            assert!(resp.is_ok(), "{:?}", resp);
            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;

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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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
fn test_masked_key_aes_bulk_gen_with_rollback_error_after_dma_out_after_exhaust_keys() {
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
            let mut masked_key =
                MborByteArray::from_slice(&[]).expect("Failed to create temp array");

            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => {
                        masked_key = val.data.masked_key;
                        key_id = val.data.key_id;
                    }
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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
                Err(DdiError::DdiError(201)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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
fn test_masked_key_aes_bulk_gen_with_rollback_error_after_dma_end() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            if get_device_kind(dev) != DdiDeviceKind::Physical {
                println!("Physical device NOT found. Test only supported on physical device.");
                return;
            }

            let resp = generate_aes_bulk_256_key(dev, &session_id, Some(1));
            assert!(resp.is_ok(), "{:?}", resp);
            let resp = resp.unwrap();
            let key_id = resp.data.key_id;
            let masked_key = resp.data.masked_key;

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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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
fn test_masked_key_aes_bulk_gen_with_rollback_error_after_dma_end_after_exhaust_keys() {
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
            let mut masked_key =
                MborByteArray::from_slice(&[]).expect("Failed to create temp array");
            // Exhaust the key vault with App keys
            loop {
                match generate_aes_bulk_256_key(dev, &session_id, Some(key_tag)) {
                    Err(DdiError::DdiStatus(DdiStatus::ReachedMaxAesBulkKeys)) => break,
                    Err(err) => panic!("Unexpected error code: {:?}", err),
                    Ok(val) => {
                        masked_key = val.data.masked_key;
                        key_id = val.data.key_id;
                    }
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

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
                Err(DdiError::DdiError(198)) => (),
                Err(err) => panic!("Unexpected error code: {:?}", err),
                Ok(_) => panic!("Unexpected success response"),
            }

            let resp = generate_aes_bulk_256_key(dev, &app_sess_id, Some(3355));
            assert!(resp.is_ok(), "resp: {:?}", resp);

            match helper_unmask_key(
                dev,
                Some(app_sess_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            ) {
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

fn test_masked_key_aes_gen(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: DdiAesKeySize,
) {
    if get_device_kind(dev) == DdiDeviceKind::Virtual {
        tracing::debug!(
            "Masked key test is only support in Physical platform. Skipping the test..."
        );
        return;
    }

    // Generate a key
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_aes_generate(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_size,
        Some(1),
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    let key_id = resp.data.key_id;
    let masked_key = resp.data.masked_key;

    // Try to unmask this key, it should fail because the key tag already exists
    let resp = helper_unmask_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        masked_key,
    );

    assert!(resp.is_err(), "resp {:?}", resp);

    // Encrypt the plain text with the key
    let iv = MborByteArray::new([0x8; 16], 16).expect("failed to create byte array");

    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        DdiAesOp::Encrypt,
        MborByteArray::from_slice(&RAW_MSG).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG, resp.data.msg.as_slice());

    let encrypted_msg = resp.data.msg.as_slice().to_vec();

    // Delete that key
    let resp = helper_delete_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    // Import that key with masked key (Unmask this key)
    let resp = helper_unmask_key(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        masked_key,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    let new_key_id = resp.data.key_id;

    // Decrypt the plain text
    let resp = helper_aes_encrypt_decrypt(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        new_key_id,
        DdiAesOp::Decrypt,
        MborByteArray::from_slice(encrypted_msg.as_slice()).expect("failed to create byte array"),
        iv,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);
    let resp = resp.unwrap();

    // Verify the plain text
    assert_eq!(resp.data.msg.as_slice(), RAW_MSG);
    assert_eq!(resp.data.msg.len(), RAW_MSG.len());
}

fn test_masked_key_aes_gcm_encrypt_decrypt_thread_fn(
    device_path: String,
    max_attempts: usize,
    parent_dev: &mut <DdiTest as Ddi>::Dev,
    parent_session: u16,
) {
    let ddi = DdiTest::default();
    let mut dev = ddi.open_dev(device_path.as_str()).unwrap();
    set_device_kind(&mut dev);
    let mut app_sess_id = None;
    let mut short_app_id = None;

    for _ in 0..max_attempts {
        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(&dev, TEST_CRED_ID, TEST_CRED_PIN);

        let resp = helper_open_session(
            &dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        );
        if resp.as_ref().is_err() {
            if matches!(
                resp.as_ref().unwrap_err(),
                DdiError::DdiStatus(DdiStatus::NonceMismatch)
            ) {
                continue;
            }
        }

        assert!(resp.is_ok(), "resp {:?}", resp);

        let resp = resp.unwrap();

        assert!(resp.hdr.sess_id.is_some());
        assert_eq!(resp.hdr.op, DdiOp::OpenSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        app_sess_id = Some(resp.data.sess_id);
        short_app_id = Some(resp.data.short_app_id);

        break;
    }

    let app_sess_id = app_sess_id.unwrap();
    let short_app_sess_id = short_app_id.unwrap();

    thread::sleep(std::time::Duration::from_secs(1));

    let resp = generate_aes_bulk_256_key(parent_dev, &parent_session, Some(1));
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    let key_id = resp.data.key_id;
    let key_id_aes_bulk_256 = resp.data.bulk_key_id;
    let masked_key = resp.data.masked_key;
    assert!(key_id_aes_bulk_256.is_some());

    // Try to unmask this key, it should fail because the key tag already exists
    let resp = helper_unmask_key(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        masked_key,
    );

    assert!(resp.is_err(), "resp {:?}", resp);

    // Set up requests for the gcm encrypt operations
    let aad = [0x4; 32usize];
    let iv = [0x3u8; 12];

    // Setup params for encrypt operation
    let mut mcr_fp_gcm_params: DdiAesGcmParams = DdiAesGcmParams {
        key_id: key_id_aes_bulk_256.unwrap() as u32,
        iv,
        aad: Some(aad.to_vec()),
        tag: None, // tag is not needed for encryption
        session_id: app_sess_id,
        short_app_id: short_app_sess_id,
    };

    // Execute encrypt operation
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Encrypt,
        mcr_fp_gcm_params.clone(),
        RAW_MSG.to_vec(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let encrypted_resp = resp.unwrap();

    // Ensure encrypted data length is the same as the original data
    // Ensure encrypted data is different from original data
    assert_eq!(encrypted_resp.data.len(), RAW_MSG.len());
    assert_ne!(RAW_MSG.to_vec(), encrypted_resp.data);
    let tag = encrypted_resp.tag;

    // Delete that key
    let resp = helper_delete_key(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    // Import that key with masked key (Unmask this key)
    let resp = helper_unmask_key(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        masked_key,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();
    let new_bulk_key_id = resp.data.bulk_key_id;
    assert!(new_bulk_key_id.is_some());
    let newbulk_key_id = new_bulk_key_id.unwrap();

    // Execute decrypt operation
    mcr_fp_gcm_params.tag = tag;
    mcr_fp_gcm_params.key_id = newbulk_key_id as u32;
    let resp = dev.exec_op_fp_gcm(
        DdiAesOp::Decrypt,
        mcr_fp_gcm_params.clone(),
        encrypted_resp.data.clone(),
    );

    assert!(resp.is_ok(), "resp: {:?}", resp);
    let decrypted_resp = resp.unwrap();

    assert_eq!(decrypted_resp.data.len(), RAW_MSG.len());
    assert_eq!(decrypted_resp.data, RAW_MSG);
}
