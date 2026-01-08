// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

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
                let resp = helper_rsa_mod_exp_op(
                    dev,
                    DdiOp::AesGenerateKey,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    0x1,
                    MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    DdiRsaOpType::Sign,
                );

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

// Unmask the key in DdiAesGenerateKeyResp
#[test]
fn test_aes_generate_and_unmask() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Run this test only for Mock device
            if get_device_kind(dev) != DdiDeviceKind::Virtual {
                println!("Unmask key Not supported for Physical Device.");
                return;
            }

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
            let data = resp.unwrap().data;

            let original_key_id = data.key_id;

            let masked_key = data.masked_key;
            assert!(!masked_key.is_empty());

            // Import/unmask the key
            let resp = helper_unmask_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                masked_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let data = resp.unwrap().data;
            let unmasked_key_id = data.key_id;
            assert_ne!(unmasked_key_id, original_key_id);

            // Use the two keys to AES encrypt/decrypt
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                original_key_id,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                unmasked_key_id,
                DdiAesOp::Decrypt,
                MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                    .expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            assert_eq!(resp.data.msg.data_take(), msg);
            assert_eq!(resp.data.msg.len(), msg_len);
        },
    );
}

#[test]
fn test_aes_generate_and_unmask_tampered() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Run this test only for Mock device
            if get_device_kind(dev) != DdiDeviceKind::Virtual {
                println!("Unmask key Not supported for Physical Device.");
                return;
            }

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
            let data = resp.unwrap().data;

            // Tamper
            {
                let mut masked_key = data.masked_key;

                masked_key.data_mut()[0] = masked_key.data_mut()[0].wrapping_add(1);

                // Import/unmask the key
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }

            // Truncate
            {
                let masked_key = data.masked_key;
                let data = masked_key.data_take();
                let masked_key =
                    MborByteArray::new(data, data.len() / 10).expect("failed to create byte array");

                // Import/unmask the key
                let resp = helper_unmask_key(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    masked_key,
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::MaskedKeyDecodeFailed)
                ));
            }
        },
    );
}
