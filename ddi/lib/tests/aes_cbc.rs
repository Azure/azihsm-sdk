// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

mod common;

use azihsm_ddi::*;
use azihsm_ddi_mbor::MborByteArray;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

pub fn generate_keys(dev: &mut <DdiTest as Ddi>::Dev, sess_id: u16) -> (u16, u16, u16) {
    // Generate AES key
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

    let key_id_aes_128 = resp.data.key_id;

    let resp = helper_aes_generate(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes192,
        None,
        key_props,
    );

    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let key_id_aes_192 = resp.data.key_id;

    let resp = helper_aes_generate(
        dev,
        Some(sess_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        DdiAesKeySize::Aes256,
        Some(0x1234),
        key_props,
    );
    assert!(resp.is_ok(), "resp {:?}", resp);

    let resp = resp.unwrap();

    let key_id_aes_256 = resp.data.key_id;

    (key_id_aes_128, key_id_aes_192, key_id_aes_256)
}

#[test]
fn test_aes_cbc_encrypt_decrypt_malformed_ddi() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len() as u16;
            let mut msg = [0u8; 1024];
            msg[..msg_len as usize].clone_from_slice(&raw_msg);

            {
                let resp = helper_get_api_rev_op(
                    dev,
                    DdiOp::AesEncryptDecrypt,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::DdiDecodeFailed)
                ));

                let resp = helper_get_api_rev_op(
                    dev,
                    DdiOp::AesEncryptDecrypt,
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
                    DdiOp::AesEncryptDecrypt,
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

                let resp = helper_rsa_mod_exp_op(
                    dev,
                    DdiOp::AesEncryptDecrypt,
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
fn test_aes_cbc_encrypt_decrypt_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, _, key_id_aes_256) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_256,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));

            let resp = helper_aes_encrypt_decrypt(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_256,
                DdiAesOp::Decrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
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
fn test_aes_cbc_encrypt_decrypt_msg_is_not_aligned_to_block_length() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, _, key_id_aes_256) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 510];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_256,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_256,
                DdiAesOp::Decrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_decrypt_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let imported_ecc_key = resp.data.private_key_id;

            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                imported_ecc_key,
                DdiAesOp::Encrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                imported_ecc_key,
                DdiAesOp::Decrypt,
                MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
            );

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_decrypt_incorrect_permissions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

            let resp = helper_aes_generate(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);

            let key_props = helper_key_properties(DdiKeyUsage::Unwrap, DdiKeyAvailability::App);

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
fn test_aes_cbc_encrypt_decrypt_incorrect_key_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            // With an IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    20,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                ));

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    20,
                    DdiAesOp::Decrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_err(), "resp {:?}", resp);
                assert!(matches!(
                    resp.unwrap_err(),
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                ));
            }
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_decrypt_128() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (key_id_aes_128, _, _) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            // With no IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_128,
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
                    key_id_aes_128,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }

            // With an IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_128,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_128,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_decrypt_192() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, key_id_aes_192, _) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            // With no IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_192,
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
                    key_id_aes_192,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }

            // With an IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_192,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_192,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_decrypt_256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_, _, key_id_aes_256) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 512];
            let msg_len = raw_msg.len();
            let mut msg = [0u8; 1024];
            msg[..msg_len].clone_from_slice(&raw_msg);

            // With no IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_256,
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
                    key_id_aes_256,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x0; 16], 16).expect("failed to create byte array"),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }

            // With an IV
            {
                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_256,
                    DdiAesOp::Encrypt,
                    MborByteArray::new([0x1; 1024], msg_len).expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let resp = helper_aes_encrypt_decrypt(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_id_aes_256,
                    DdiAesOp::Decrypt,
                    MborByteArray::new(resp.data.msg.data_take(), resp.data.msg.len())
                        .expect("failed to create byte array"),
                    MborByteArray::new([0x8; 16], 16).expect("failed to create byte array"),
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                assert_eq!(resp.data.msg.data_take(), msg);
                assert_eq!(resp.data.msg.len(), msg_len);
            }
        },
    );
}

#[test]
fn test_aes_cbc_iv_chaining_encrypt_then_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (key_id_aes_128, _, _) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 32]; // 32 bytes
            let msg_len = raw_msg.len();
            let input_iv = [0x1; 16];

            let mut msg_data1 = [0u8; 1024];
            msg_data1[..16].copy_from_slice(&raw_msg[0..16]);

            let mut msg_data2 = [0u8; 1024];
            msg_data2[..16].copy_from_slice(&raw_msg[16..32]);

            let mut msg_data = [0u8; 1024];
            msg_data[..msg_len].clone_from_slice(&raw_msg);

            // Encrypt the first 16 bytes
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Encrypt,
                MborByteArray::new(msg_data1, 16).expect("failed to create byte array"),
                MborByteArray::new(input_iv, 16).expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let first_encrypt_resp = resp.unwrap();

            // Encrypt the next 16 bytes using output IV from Step above
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Encrypt,
                MborByteArray::new(msg_data2, 16).expect("failed to create byte array"),
                MborByteArray::new(first_encrypt_resp.data.iv.data_take(), 16)
                    .expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let second_encrypt_resp = resp.unwrap();

            let mut combined_encrypted = [0u8; 1024];
            let first_len = first_encrypt_resp.data.msg.len();
            let second_len = second_encrypt_resp.data.msg.len();

            // Copy the first part of the encrypted data
            combined_encrypted[..first_len]
                .copy_from_slice(&first_encrypt_resp.data.msg.data()[..first_len]);

            // Copy the second part of the encrypted data
            combined_encrypted[first_len..first_len + second_len]
                .copy_from_slice(&second_encrypt_resp.data.msg.data()[..second_len]);

            //  Decrypt full 32 bytes in one operation using the initial IV
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Decrypt,
                MborByteArray::new(combined_encrypted, 32).expect("failed to create byte array"),
                MborByteArray::new(input_iv, 16).expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let decrypt_resp = resp.unwrap();

            // Verify
            assert_eq!(decrypt_resp.data.msg.data_take(), msg_data);
            assert_eq!(decrypt_resp.data.msg.len(), msg_len);
        },
    );
}

#[test]
fn test_aes_cbc_encrypt_then_iv_chaining_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (key_id_aes_128, _, _) = generate_keys(dev, session_id);

            let raw_msg = [1u8; 32]; // 32 bytes
            let msg_len = raw_msg.len();
            let input_iv = [0x1; 16];

            let mut msg_data = [0u8; 1024];
            msg_data[..msg_len].clone_from_slice(&raw_msg);

            // Encrypt the full 32 bytes in one operation
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Encrypt,
                MborByteArray::new(msg_data, msg_len).expect("failed to create byte array"),
                MborByteArray::new(input_iv, 16).expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let encrypt_resp = resp.unwrap();

            let mut resp_data1 = [0u8; 1024];
            resp_data1[..16].copy_from_slice(&encrypt_resp.data.msg.data()[0..16]);
            let mut resp_data2 = [0u8; 1024];
            resp_data2[..16].copy_from_slice(&encrypt_resp.data.msg.data()[16..32]);

            // Decrypt the first 16 bytes
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Decrypt,
                MborByteArray::new(resp_data1, 16).expect("failed to create byte array"),
                MborByteArray::new(input_iv, 16).expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let first_decrypt_resp = resp.unwrap();

            // Decrypt the next 16 bytes using output IV from Step above
            let resp = helper_aes_encrypt_decrypt(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                key_id_aes_128,
                DdiAesOp::Decrypt,
                MborByteArray::new(resp_data2, 16).expect("failed to create byte array"),
                MborByteArray::new(first_decrypt_resp.data.iv.data_take(), 16)
                    .expect("failed to create byte array"),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
            let second_decrypt_resp = resp.unwrap();

            println!("second_decrypt_resp{:?}", second_decrypt_resp);

            let mut combined_decrypted = [0u8; 32];
            combined_decrypted[..16].copy_from_slice(&first_decrypt_resp.data.msg.data()[..16]);
            combined_decrypted[16..32].copy_from_slice(&second_decrypt_resp.data.msg.data()[..16]);

            let len = first_decrypt_resp.data.msg.len() + second_decrypt_resp.data.msg.len();

            // Verify
            assert_eq!(combined_decrypted, raw_msg);

            assert_eq!(len, msg_len);
        },
    );
}
