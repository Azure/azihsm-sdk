// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use std::cmp::min;
use std::thread;

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

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

fn test_masked_key_aes_gen(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_size: DdiAesKeySize,
) {
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

    let resp = helper_get_new_key_id_from_unmask(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (new_key_id, _, _) = resp.unwrap();

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
        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            &dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

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

    let resp = generate_aes_bulk_256_key(
        parent_dev,
        &parent_session,
        Some(1),
        DdiAesKeySize::AesGcmBulk256Unapproved,
    );
    assert!(resp.is_ok(), "resp: {:?}", resp);
    let resp = resp.unwrap();

    let key_id = resp.data.key_id;
    let key_id_aes_bulk_256 = resp.data.bulk_key_id;
    let masked_key = resp.data.masked_key;
    assert!(key_id_aes_bulk_256.is_some());

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

    let resp = helper_get_new_key_id_from_unmask(
        parent_dev,
        Some(parent_session),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        true,
        masked_key,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);
    let (_, new_bulk_key_id, _) = resp.unwrap();

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

// Create session key, delete the key
// Unmask the key, should still be session key
#[test]
fn test_unmask_session_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Import/unmask the key
            let key_id = {
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    masked_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let data = resp.unwrap().data;
                data.key_id
            };

            // Check if this key is session key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id,
            );
            // Should fail
            assert!(resp.is_err());

            // Close session and reopen
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Check if the session key still exists
            // By using it to encrypt
            {
                let raw_msg = [1u8; 512];
                let msg_len = raw_msg.len();
                let mut msg = [0u8; 1024];
                msg[..msg_len].clone_from_slice(&raw_msg);

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}

// Create named key, delete the key
// Unmask the key, should still be named key
#[test]
fn test_unmask_named_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            const KEY_TAG: u16 = 0x1234;
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            // Create a named key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                Some(KEY_TAG),
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            // Check if this key is named key
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());

            // Key should still be there
            let resp = helper_open_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                KEY_TAG,
            );
            // Should pass
            assert!(resp.is_ok());
        },
    );
}

// Create session key
// Confirm unmasking into different session fails
#[test]
fn test_unmask_session_key_different_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::Session);

            // Create a session key
            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;

            let key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Delete the original key
            {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            // Close session and open session with new seed
            let session_id = {
                let resp = helper_close_session(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let new_session_seed = [42u8; 48];
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    dev,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    new_session_seed,
                );

                let resp = helper_open_session(
                    dev,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential.clone(),
                    pub_key.clone(),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.hdr.sess_id.is_some());
                assert_eq!(resp.hdr.op, DdiOp::OpenSession);
                assert_eq!(resp.hdr.status, DdiStatus::Success);

                resp.data.sess_id
            };

            // Import/unmask the key; should fail
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}
