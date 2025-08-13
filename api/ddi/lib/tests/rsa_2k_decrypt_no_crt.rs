// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_2k_decrypt_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let session_id = 20;
            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_key_num_table() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: 0x0300,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_key_num_entry() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: 0x0020,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::KeyNotFound)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import a key with a wrong type
            let key_id_wrong_type = store_aes_keys(dev, session_id);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_wrong_type,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidKeyType)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_message_zero_data() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_rsa_2k_decrypt_incorrect_message_zero_data for virtual device"
                );
                return;
            }

            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::new([0x0; 512], 256).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt_incorrect_message_large_data() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Skip test for virtual device as it doesn't check for RSA mod exp data
            // This is a FIPS only requirement
            let device_kind = get_device_kind(dev);
            if device_kind != DdiDeviceKind::Physical {
                tracing::debug!(
                    "Skipped test_rsa_2k_decrypt_incorrect_message_large_data for virtual device"
                );
                return;
            }

            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::new([0xff; 512], 256).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_rsa_2k_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::from_slice(&[0x1; 256]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_rsa_2k_encrypt_and_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let orig_x = [0x1u8; 512];
            let data_len_to_test = 190;
            let resp = rsa_encrypt_local_openssl(
                &TEST_RSA_2K_PUBLIC_KEY,
                &orig_x,
                data_len_to_test,
                DdiRsaCryptoPadding::Oaep,
                Some(DdiHashAlgorithm::Sha256),
            );

            let mut encrypted_data = [0u8; 512];
            encrypted_data[..resp.len()].copy_from_slice(resp.as_slice());
            let encrypted_data_len = resp.len();

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::new(encrypted_data, encrypted_data_len)
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let mut padded_data = [0u8; 512];
            padded_data[..resp.data.x.len()]
                .copy_from_slice(&resp.data.x.data()[..resp.data.x.len()]);

            let unpadded_data_result = RsaEncoding::decode_oaep(
                &mut padded_data[..resp.data.x.len()],
                None,
                2048 / 8,
                RsaDigestKind::Sha256,
                crypto_sha256,
            );
            assert!(unpadded_data_result.is_ok());
            let unpadded_data = unpadded_data_result.unwrap();

            assert_eq!(orig_x[..data_len_to_test], unpadded_data);
        },
    );
}
