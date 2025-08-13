// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_sim::crypto::rsa::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_mod_exp_no_session() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_incorrect_session_id() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_incorrect_key_num_table() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_incorrect_key_num_entry() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_incorrect_key_type() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_incorrect_permissions() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 2);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidPermissions)
            ));
        },
    );
}

#[test]
fn test_rsa_mod_exp() {
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
                    y: MborByteArray::new([0x1; 512], 256).expect("failed to create byte array"),
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
fn test_rsa_mod_exp_encrypt_and_decrypt() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa2k_pub, key_id_rsa2k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::EncryptDecrypt, 2);

            let orig_x = [0x1u8; 512];
            let data_len_to_test = 256;

            let data = &orig_x[..data_len_to_test];

            let rsa_pub_key = RsaPublicKey::from_der(&TEST_RSA_2K_PUBLIC_KEY, None)
                .expect("failed to create RSA public key from DER");
            let encrypted_data = rsa_pub_key
                .encrypt(data, RsaCryptoPadding::None, None)
                .expect("failed to encrypt data with RSA public key");

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa2k_priv,
                    y: MborByteArray::from_slice(&encrypted_data)
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Decrypt,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert_eq!(
                orig_x[..data_len_to_test],
                resp.data.x.data()[..resp.data.x.len()]
            );
        },
    );
}
