// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn create_key(dev: &mut <DdiTest as Ddi>::Dev, sess_id: u16) -> u16 {
    let key_props = helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

    let resp = helper_aes_generate(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes128,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    resp.data.key_id
}

#[test]
fn test_delete_key_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_to_delete = create_key(dev, session_id);

            let resp = helper_delete_key(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
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
fn test_delete_key_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_to_delete = create_key(dev, session_id);

            let session_id = 20;

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
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
fn test_delete_key_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0300,
            );
            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_delete_key_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0x0020,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_delete_key_unwrapping_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (unwrapping_key_id, _, _) = get_unwrapping_key(dev, session_id);

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unwrapping_key_id,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::CannotDeleteInternalKeys)
            ));
        },
    );
}

#[test]
fn test_delete_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_to_delete = create_key(dev, session_id);

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let raw_msg = [1u8; 512];

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
                DdiAesOp::Encrypt,
                MborByteArray::from_slice(&raw_msg).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );
            println!("{:?}", resp);
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_delete_key_multiple() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_to_delete = create_key(dev, session_id);

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_delete_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_to_delete,
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_import_delete_aesbulk256_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let max_keys = get_device_info(ddi, path).tables as u16 * 7;
            let mut key_ids = vec![];
            for i in 0..max_keys {
                let resp = rsa_secure_import_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    &TEST_RSA_2K_PRIVATE_KEY,
                    DdiKeyClass::Rsa,
                    DdiKeyUsage::EncryptDecrypt,
                    Some(i + 1),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                key_ids.push(resp.unwrap().data.key_id);
            }
            for (i, key_id) in key_ids.into_iter().enumerate() {
                let resp = helper_delete_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = helper_open_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    i as u16 + 1,
                );
                assert!(resp.is_err(), "resp {:?}", resp);
            }
        },
    );
}
