// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use crypto::rand::rand_bytes;
use crypto::CryptoRsaSignaturePadding;
use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use rsa_padding::RsaDigestKind;
use rsa_padding::RsaEncoding;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_rsa_3k_sign_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let session_id = 20;
            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_incorrect_key_num_table() {
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
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_incorrect_key_num_entry() {
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
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_incorrect_key_type() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Import a key with a wrong type
            let (private_key_id_wrong_type, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: private_key_id_wrong_type,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_incorrect_permission() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let mut der = [0u8; 3072];
            der[..TEST_RSA_3K_PRIVATE_KEY.len()].copy_from_slice(&TEST_RSA_3K_PRIVATE_KEY);

            let req = DdiDerKeyImportCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::DerKeyImport,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiDerKeyImportReq {
                    der: MborByteArray::new(der, TEST_RSA_3K_PRIVATE_KEY.len())
                        .expect("failed to create byte array"),
                    key_class: DdiKeyClass::Rsa,
                    key_tag: None,
                    key_properties: helper_key_properties(
                        DdiKeyUsage::EncryptDecrypt,
                        DdiKeyAvailability::App,
                    ),
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: resp.data.key_id,
                    y: MborByteArray::from_slice(&[0x1; 32]).expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
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
fn test_rsa_3k_sign_and_verify_pkcs15_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 20];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 3072 / 8, RsaDigestKind::Sha1).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x95, 0x2B, 0x66, 0xFD, 0xB0, 0xAC, 0x3C, 0x69, 0x0A, 0x59, 0xE4, 0xE2, 0x4E,
                    0xD6, 0x0A, 0x27, 0x28, 0x44, 0x2A, 0xE5, 0xCE, 0x87, 0x16, 0xAC, 0xF4, 0xAD,
                    0xD4, 0x7D, 0x68, 0xD8, 0x48, 0x23, 0x03, 0x3D, 0x6D, 0x0C, 0x45, 0xA7, 0x09,
                    0x29, 0xDF, 0x08, 0x5F, 0x49, 0x3B, 0x9A, 0x4C, 0x2B, 0xC5, 0x31, 0x4F, 0x2C,
                    0x9A, 0x53, 0x70, 0x00, 0xD3, 0x56, 0xA3, 0xA3, 0x24, 0x45, 0x7D, 0x1E, 0x0D,
                    0x6D, 0x0B, 0x6E, 0x9F, 0x76, 0x32, 0x5F, 0x3B, 0x4E, 0xF2, 0x20, 0x3B, 0xC8,
                    0xDA, 0x69, 0xC3, 0x87, 0x4E, 0x86, 0xB8, 0x8D, 0x05, 0x46, 0xB2, 0x80, 0x3B,
                    0xC0, 0x20, 0x43, 0xA0, 0xBA, 0x05, 0xAB, 0xC9, 0xE9, 0xE7, 0xAF, 0x9B, 0xF1,
                    0x1E, 0x3B, 0x09, 0xAE, 0x6F, 0x42, 0xAC, 0x8C, 0x2E, 0x99, 0xDE, 0xF6, 0x2F,
                    0xF1, 0x96, 0xE2, 0x37, 0x0E, 0xE3, 0x02, 0xEF, 0x42, 0x5D, 0x33, 0x20, 0x99,
                    0xC5, 0x72, 0x72, 0x34, 0xB0, 0x42, 0xEB, 0x32, 0xF0, 0x00, 0xBC, 0xBD, 0xA6,
                    0x1A, 0x26, 0xB0, 0x99, 0xD7, 0x00, 0x71, 0x04, 0xC8, 0xE3, 0x22, 0x77, 0xB8,
                    0x87, 0xA8, 0xA9, 0x60, 0x83, 0x2B, 0xA9, 0xFD, 0x6D, 0x54, 0x12, 0xE6, 0xCC,
                    0x03, 0x17, 0xF2, 0xD6, 0xD4, 0x03, 0x68, 0xB0, 0x08, 0xFF, 0x3E, 0x3B, 0xDA,
                    0x5A, 0xC1, 0x46, 0x18, 0x62, 0xF5, 0xD9, 0x8E, 0x20, 0x72, 0x12, 0x71, 0xFB,
                    0xFF, 0xAE, 0x91, 0xA3, 0x8F, 0x92, 0x4B, 0x1F, 0x07, 0xAA, 0x55, 0x9D, 0x2E,
                    0xE9, 0x12, 0xA2, 0xC2, 0x14, 0x90, 0x7F, 0xDB, 0x8B, 0x68, 0x3D, 0xC9, 0x93,
                    0xF1, 0x4D, 0x52, 0xBB, 0x08, 0x47, 0x5E, 0x3A, 0x3A, 0xC1, 0x1A, 0x50, 0xCD,
                    0xBE, 0xE5, 0xB3, 0x74, 0xEB, 0x07, 0x81, 0xC5, 0x16, 0x7F, 0x70, 0xF2, 0x9C,
                    0x0A, 0xDB, 0x01, 0xE1, 0x87, 0x5A, 0x5F, 0xE7, 0xA6, 0x8E, 0x65, 0x99, 0x79,
                    0x9D, 0xFF, 0x1E, 0x52, 0x3D, 0xCC, 0x99, 0xB8, 0x5B, 0x6F, 0x76, 0x7A, 0x1F,
                    0xF7, 0x6A, 0x1C, 0xAB, 0x4D, 0x85, 0x6F, 0xE9, 0xFD, 0x5F, 0x8C, 0x4E, 0x89,
                    0x08, 0xB0, 0x57, 0x8D, 0xA5, 0xEF, 0x0D, 0x21, 0xA6, 0xA0, 0xDB, 0x96, 0x5B,
                    0xB1, 0x3E, 0xFB, 0xDA, 0xF9, 0x91, 0x53, 0x6B, 0xEC, 0x90, 0xFE, 0x92, 0xBC,
                    0xE3, 0xC0, 0x60, 0xB4, 0x29, 0xAE, 0x7B, 0x0A, 0xA3, 0x8B, 0xC4, 0xED, 0x5A,
                    0x79, 0xF4, 0x3E, 0x8A, 0xCB, 0xD6, 0xD7, 0x10, 0xDE, 0xAD, 0xD3, 0x19, 0x6E,
                    0xFC, 0xD8, 0x6E, 0x68, 0xB9, 0x5F, 0x8F, 0xF6, 0x7C, 0xBC, 0xB0, 0x69, 0x1A,
                    0x71, 0x1F, 0x68, 0x82, 0x8D, 0xAE, 0x97, 0xE3, 0x44, 0x0E, 0x1C, 0x5E, 0x97,
                    0x2C, 0x2D, 0x4B, 0x05, 0x56, 0x7A, 0x88, 0xEC, 0x52, 0xBD, 0x6B, 0x20, 0xED,
                    0x65, 0x99, 0x1F, 0x09, 0xEA, 0x4B, 0xA5
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 20],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha1),
                None,
            );
            assert!(result);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pkcs15_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 32];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 3072 / 8, RsaDigestKind::Sha256).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x9C, 0x5E, 0x45, 0x21, 0x1A, 0xB9, 0x2C, 0xF5, 0xD5, 0xAD, 0x2B, 0x0F, 0x96,
                    0x68, 0x21, 0xF3, 0xBC, 0xD2, 0xD7, 0xA9, 0xF0, 0xFC, 0xA3, 0x6A, 0x72, 0x06,
                    0x62, 0x5A, 0x05, 0x33, 0x23, 0xE1, 0xBD, 0xFB, 0x45, 0x29, 0x75, 0x0C, 0xDE,
                    0x1A, 0xCF, 0x09, 0x9A, 0x4C, 0x2D, 0x73, 0xE1, 0x70, 0xC7, 0x04, 0x1E, 0x1F,
                    0x3E, 0xAC, 0x3F, 0xE9, 0x7A, 0xFE, 0x21, 0x05, 0x9D, 0x0F, 0x55, 0x4F, 0xF1,
                    0xC2, 0xED, 0xA6, 0x3C, 0x94, 0xF0, 0x34, 0x06, 0x6A, 0xFD, 0x20, 0x35, 0x0F,
                    0x6F, 0x24, 0xAE, 0x06, 0xD0, 0x15, 0xB8, 0xDD, 0xE0, 0x63, 0x47, 0xF5, 0xA5,
                    0x45, 0x76, 0x64, 0xFF, 0xD7, 0x7D, 0x9F, 0x8A, 0x0D, 0x61, 0xAD, 0x51, 0xD3,
                    0x3E, 0x75, 0x17, 0x07, 0xE0, 0xFB, 0x6F, 0x6E, 0xC1, 0x10, 0xF1, 0x50, 0xE5,
                    0x0B, 0x0B, 0xA0, 0x6F, 0x88, 0xCF, 0x12, 0xC7, 0x34, 0x76, 0x5E, 0xAC, 0xEC,
                    0x93, 0xD0, 0x2A, 0x43, 0x4E, 0xEB, 0x2B, 0xE1, 0x7B, 0x2C, 0xA2, 0xFD, 0x28,
                    0x7F, 0xEE, 0x3F, 0x41, 0xF6, 0x17, 0xA2, 0x4C, 0x65, 0xDB, 0x54, 0x72, 0x2A,
                    0xA6, 0xAB, 0xA1, 0x31, 0x1C, 0x41, 0xBF, 0xE8, 0x8D, 0xBB, 0xDD, 0xF8, 0xD0,
                    0xD2, 0x0E, 0xCF, 0x39, 0x2F, 0xDB, 0xCC, 0xB6, 0x78, 0x1E, 0x5A, 0x47, 0x10,
                    0x99, 0xAC, 0x62, 0xE7, 0x8E, 0x4E, 0x74, 0x87, 0x31, 0xEE, 0xA6, 0x6F, 0x00,
                    0xEB, 0x26, 0x38, 0x2D, 0xAB, 0x5C, 0x2D, 0x82, 0xE7, 0x04, 0x75, 0x14, 0xCE,
                    0x64, 0x09, 0x14, 0xA9, 0x81, 0xC2, 0xD4, 0x50, 0x7F, 0xFE, 0x2C, 0xCC, 0x24,
                    0xE9, 0x4C, 0x4A, 0x0C, 0x01, 0xDA, 0xDF, 0x9A, 0xA4, 0x8D, 0x12, 0x2F, 0x0A,
                    0x40, 0xC9, 0x8C, 0x48, 0x6C, 0x26, 0x23, 0xA0, 0x5F, 0xF0, 0x2E, 0xAF, 0xD7,
                    0xFA, 0xDE, 0x7C, 0xF0, 0xC6, 0xE5, 0xB4, 0x6D, 0xD8, 0x94, 0x3B, 0xA4, 0xFD,
                    0xF6, 0x83, 0xB0, 0x80, 0x33, 0x10, 0x23, 0x4E, 0xA8, 0x46, 0xF7, 0x91, 0x0D,
                    0xEF, 0x8F, 0x21, 0x96, 0xD4, 0x71, 0xCF, 0x46, 0xF9, 0xD7, 0x69, 0xAC, 0x90,
                    0x45, 0x98, 0x46, 0x3C, 0x7B, 0xAF, 0x96, 0x8E, 0xCA, 0x34, 0x27, 0xDA, 0xF6,
                    0x48, 0x9C, 0x6C, 0x22, 0xAE, 0x37, 0x07, 0xB4, 0x24, 0x32, 0x92, 0x20, 0x4C,
                    0x18, 0x37, 0x2B, 0xEB, 0x7F, 0x17, 0x44, 0x25, 0x4D, 0xC7, 0x8B, 0x59, 0x69,
                    0x72, 0xD5, 0x0F, 0xB1, 0x9C, 0xF9, 0x8F, 0xAB, 0x7E, 0xA0, 0x4B, 0x1A, 0x50,
                    0xB2, 0xE5, 0x0E, 0x64, 0x26, 0xF9, 0xA3, 0xCD, 0x2A, 0xD8, 0x9E, 0x4E, 0x60,
                    0xDB, 0x87, 0xB0, 0x56, 0x5E, 0x62, 0xC7, 0x9D, 0xA7, 0xB7, 0x0D, 0xF3, 0xC4,
                    0x54, 0x12, 0x66, 0xBE, 0x81, 0xDE, 0x41, 0x27, 0xFD, 0xAD, 0x06, 0xC0, 0xE5,
                    0xC6, 0x16, 0x14, 0xDB, 0x98, 0x14, 0x73
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 32],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha256),
                None,
            );
            assert!(result);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pkcs15_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 48];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 3072 / 8, RsaDigestKind::Sha384).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x44, 0xFF, 0x97, 0x04, 0x92, 0xBF, 0x7A, 0x6A, 0x30, 0x4C, 0x07, 0x1C, 0x21,
                    0xCE, 0x48, 0x3D, 0x41, 0x67, 0x4B, 0x6F, 0x0E, 0x7D, 0x8D, 0x6B, 0x3C, 0x27,
                    0x7C, 0x13, 0xFF, 0xD8, 0x8D, 0x4B, 0xF6, 0xD5, 0x7D, 0x28, 0x15, 0xA6, 0x71,
                    0x30, 0xDD, 0x76, 0xE3, 0x6B, 0xD2, 0x71, 0x66, 0x8D, 0x5B, 0x30, 0x59, 0xC4,
                    0x58, 0x9D, 0x36, 0x82, 0x7B, 0x14, 0x3E, 0xD7, 0xDD, 0x90, 0x3D, 0x8C, 0x65,
                    0x53, 0x58, 0x7C, 0x1E, 0x32, 0xD7, 0x4F, 0xC9, 0x9C, 0x9A, 0x1C, 0x4A, 0x21,
                    0x97, 0xE9, 0x36, 0xD4, 0x31, 0x5C, 0x59, 0x50, 0x33, 0x93, 0x5E, 0xB5, 0x6A,
                    0x02, 0x32, 0x24, 0xE8, 0xF5, 0x5D, 0x96, 0x1A, 0xAC, 0xA1, 0xEE, 0xF7, 0xD8,
                    0xCA, 0x3A, 0x06, 0x0C, 0x19, 0xB6, 0xBD, 0x21, 0xE5, 0x29, 0x6C, 0x75, 0x98,
                    0x1C, 0x96, 0xE8, 0xA4, 0x71, 0x37, 0xDC, 0xE0, 0xF8, 0x87, 0x57, 0x03, 0x77,
                    0x26, 0xC5, 0xB9, 0xC5, 0x36, 0x99, 0x1D, 0xCB, 0x88, 0x31, 0x64, 0x3A, 0x35,
                    0x81, 0xAE, 0x8F, 0xC3, 0x2C, 0x10, 0x67, 0xFB, 0x9F, 0xC0, 0x56, 0xAC, 0xBA,
                    0x82, 0x8F, 0xE7, 0xE5, 0x99, 0xF7, 0x99, 0x50, 0x06, 0x1B, 0xBF, 0xAB, 0x04,
                    0xD6, 0xA3, 0x1B, 0xA1, 0xF7, 0x7A, 0x95, 0x36, 0x8C, 0xFF, 0x07, 0xF6, 0x24,
                    0xC7, 0xE8, 0x1D, 0xFC, 0x32, 0x14, 0x02, 0x84, 0x02, 0xC7, 0x31, 0xBF, 0x8D,
                    0x5F, 0xD1, 0xEF, 0xA4, 0x1B, 0x43, 0xD3, 0x77, 0xBF, 0xD6, 0x36, 0x6E, 0x40,
                    0xB1, 0x74, 0xF2, 0xF0, 0x11, 0xDF, 0xDB, 0xAE, 0xA8, 0x36, 0xF5, 0xA1, 0x64,
                    0x04, 0x9C, 0x0D, 0xEB, 0xD8, 0x78, 0x28, 0x3D, 0x0F, 0x61, 0xFB, 0x76, 0x33,
                    0x82, 0x96, 0xD8, 0x99, 0x3D, 0xF3, 0x1C, 0x9C, 0xEC, 0x88, 0x3C, 0xB9, 0xF7,
                    0xAD, 0x54, 0x49, 0xEE, 0xB0, 0x11, 0x03, 0xDA, 0x52, 0x70, 0x99, 0xD7, 0xC0,
                    0xD9, 0x01, 0xA1, 0x9D, 0x50, 0x22, 0x83, 0x64, 0x6B, 0x15, 0x4C, 0xAB, 0x13,
                    0xFC, 0x7B, 0xFF, 0x72, 0xF1, 0x7B, 0x08, 0xA5, 0x3E, 0xAC, 0x91, 0x2E, 0x58,
                    0xFC, 0x78, 0x6E, 0x74, 0xD5, 0x26, 0xCB, 0x02, 0xAA, 0x32, 0x0B, 0x02, 0x2C,
                    0x1A, 0x27, 0x6E, 0x1A, 0xA3, 0xE0, 0x9F, 0x3C, 0x57, 0xF6, 0x81, 0x92, 0xC3,
                    0x94, 0xF6, 0x8D, 0x9B, 0x6D, 0x0F, 0xF9, 0x8A, 0x41, 0xAF, 0xA9, 0x48, 0x0E,
                    0xD0, 0x3D, 0xB8, 0x22, 0xBA, 0x99, 0x8D, 0xEB, 0x4B, 0xB1, 0xA5, 0x4C, 0x51,
                    0x49, 0x10, 0xEE, 0x2C, 0x5F, 0x87, 0x9C, 0x7A, 0x76, 0xFA, 0xD2, 0x9F, 0x3A,
                    0x5C, 0x03, 0xC9, 0xD8, 0x2B, 0xE1, 0x8A, 0x94, 0x7D, 0x66, 0xCC, 0x28, 0x94,
                    0x62, 0x3C, 0xAA, 0x59, 0x5F, 0x9D, 0xB6, 0x7A, 0x4C, 0xB7, 0x08, 0x10, 0x1A,
                    0xBD, 0x5B, 0x4B, 0xCB, 0x9F, 0xC6, 0xDB
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 48],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha384),
                None,
            );
            assert!(result);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pkcs15_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 64];
            let padded_hash =
                RsaEncoding::encode_pkcs_v15(&hash, 3072 / 8, RsaDigestKind::Sha512).unwrap();

            let mut y = [0u8; 512];
            y[..padded_hash.len()].copy_from_slice(&padded_hash);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(
                sig_no_crt_key,
                [
                    0x08, 0xAB, 0x11, 0x46, 0x48, 0x58, 0xCE, 0x47, 0xB1, 0xE8, 0xE8, 0xC3, 0x6B,
                    0xDF, 0xEB, 0xAA, 0x6E, 0xE6, 0x6F, 0x6A, 0x78, 0x5A, 0x39, 0x5A, 0x24, 0x92,
                    0xD6, 0x15, 0xCF, 0x09, 0xD6, 0x3E, 0xB7, 0x57, 0xE3, 0xF9, 0x9B, 0xDD, 0x40,
                    0xA3, 0xF9, 0xF5, 0xFE, 0xE2, 0x55, 0x03, 0xE7, 0xF1, 0x5D, 0xAA, 0x64, 0x78,
                    0x52, 0x2A, 0x67, 0xEC, 0x92, 0x09, 0x25, 0x31, 0x9B, 0x47, 0x2A, 0xA3, 0xD5,
                    0x40, 0xBB, 0x89, 0x56, 0x0C, 0x66, 0x85, 0x51, 0x64, 0x9B, 0x1A, 0xC1, 0x89,
                    0xCB, 0x02, 0x75, 0x11, 0x7A, 0xFB, 0xB2, 0xEE, 0xBB, 0x19, 0x71, 0x89, 0xD0,
                    0x60, 0xED, 0xF0, 0xEF, 0x06, 0xC6, 0x10, 0xCD, 0xB7, 0xED, 0x08, 0xF4, 0xB7,
                    0x2C, 0x5F, 0xA2, 0x81, 0xD0, 0xB8, 0x40, 0xD5, 0xED, 0xB8, 0xAA, 0xFE, 0xBE,
                    0xBA, 0xE1, 0xC9, 0x00, 0x60, 0x49, 0x43, 0xA5, 0x93, 0x6C, 0x79, 0xB7, 0x01,
                    0x31, 0x38, 0x17, 0xBA, 0xCC, 0x04, 0xC8, 0x9B, 0xA4, 0x32, 0xDF, 0x93, 0x86,
                    0x1F, 0x57, 0x71, 0x34, 0x39, 0xAB, 0x37, 0xCF, 0x29, 0x41, 0xEE, 0x2D, 0x58,
                    0x4C, 0x12, 0xFA, 0x5B, 0xAF, 0x03, 0x18, 0x7B, 0x2A, 0x2B, 0x73, 0x21, 0xA9,
                    0xDD, 0xDC, 0x48, 0xDA, 0xBE, 0x01, 0xF9, 0x6E, 0x7D, 0x68, 0x85, 0x1F, 0xD1,
                    0x55, 0x1E, 0xE9, 0x69, 0xBE, 0x5C, 0xED, 0xA8, 0x5F, 0x7B, 0xB6, 0x77, 0x0A,
                    0xD3, 0x59, 0x49, 0x01, 0xF8, 0x2E, 0x82, 0x44, 0x8A, 0x47, 0x32, 0xC7, 0x52,
                    0x3B, 0xCB, 0x1E, 0x16, 0x24, 0xB2, 0x5A, 0x65, 0xBD, 0x35, 0x5D, 0x2B, 0x1B,
                    0x17, 0xDE, 0x1D, 0x26, 0xB0, 0x7F, 0x59, 0x3A, 0x05, 0x7B, 0xB3, 0xB5, 0xFD,
                    0x95, 0xAB, 0x94, 0xA1, 0xF8, 0xB6, 0xEE, 0x2B, 0x32, 0xC4, 0x83, 0xB3, 0xF7,
                    0x29, 0x54, 0xEB, 0x4C, 0x96, 0x92, 0x97, 0x39, 0xF0, 0x6B, 0x8E, 0xCE, 0x32,
                    0xA5, 0xB0, 0x25, 0x2D, 0xE6, 0x76, 0x90, 0x39, 0xB7, 0x2D, 0xC1, 0x27, 0xFD,
                    0xBD, 0x5C, 0x85, 0x45, 0x9B, 0xA7, 0x22, 0x9D, 0x8B, 0xB2, 0x51, 0x95, 0x6D,
                    0x99, 0x93, 0x4A, 0x17, 0xF3, 0xCF, 0x98, 0xAA, 0x5B, 0x8B, 0x01, 0x14, 0x38,
                    0xA3, 0x53, 0x69, 0x43, 0x66, 0x40, 0xFA, 0x16, 0x6D, 0xB5, 0x8E, 0xF0, 0xBD,
                    0xAC, 0x48, 0xAF, 0x66, 0x60, 0x0E, 0xF6, 0x24, 0xD8, 0xFF, 0x22, 0x81, 0x5F,
                    0x84, 0x47, 0x5A, 0xDC, 0xB8, 0x3C, 0x8B, 0x97, 0xEB, 0xF0, 0x0C, 0xF2, 0x33,
                    0xC7, 0x5C, 0xBF, 0x63, 0x1C, 0xA5, 0xE9, 0x25, 0x6A, 0xEE, 0x5E, 0x0C, 0x16,
                    0xA0, 0xC4, 0xE1, 0x78, 0xAF, 0x24, 0x3E, 0xAD, 0x23, 0x7D, 0x97, 0xD8, 0x66,
                    0xD8, 0xC8, 0x61, 0x39, 0xAC, 0xB2, 0x6F, 0xFA, 0xE6, 0x47, 0xA0, 0x5D, 0x2E,
                    0x6E, 0xA6, 0x6F, 0xE5, 0xC3, 0x53, 0x30
                ]
            );

            let result = rsa_verify_local_openssl(
                &TEST_RSA_3K_PUBLIC_KEY,
                &resp.data.x.data()[..resp.data.x.len()],
                &[0x1; 64],
                CryptoRsaSignaturePadding::Pkcs1_5,
                Some(DdiHashAlgorithm::Sha512),
                None,
            );
            assert!(result);

            let req = DdiRsaModExpCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::RsaModExp,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiRsaModExpReq {
                    key_id: key_id_rsa3k_priv_crt,
                    y: MborByteArray::new(y, padded_hash.len())
                        .expect("failed to create byte array"),
                    op_type: DdiRsaOpType::Sign,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

            assert_eq!(sig_no_crt_key, sig_crt_key);
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pss_sha1() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 20];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha1,
                    crypto_sha1,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x19, 0x8B, 0x48, 0x68, 0x16, 0xA9, 0x5C, 0x70, 0x16, 0xC7, 0x7E, 0xCD,
                        0x06, 0x86, 0x97, 0x0A, 0x48, 0xF7, 0xC5, 0x43, 0xD4, 0x6C, 0x1B, 0x7F,
                        0x48, 0xE4, 0xAA, 0xA3, 0x23, 0xD0, 0x52, 0x40, 0x6C, 0xB8, 0xA1, 0x27,
                        0xB4, 0xA6, 0x90, 0x2D, 0x4E, 0x0C, 0x5E, 0x18, 0xC7, 0x5D, 0x37, 0x6C,
                        0x1B, 0xFF, 0x9C, 0x90, 0xE1, 0x24, 0x44, 0xA3, 0x9A, 0x63, 0x1A, 0x77,
                        0x5E, 0x37, 0x16, 0x79, 0x0D, 0xB5, 0x4A, 0x1A, 0xA2, 0x75, 0x95, 0x26,
                        0x6D, 0x20, 0x10, 0x8A, 0x74, 0x7D, 0xDD, 0x1C, 0xEE, 0x1E, 0x9B, 0x50,
                        0x11, 0x34, 0xC8, 0x60, 0x14, 0x17, 0x82, 0xD5, 0xA5, 0x50, 0x02, 0xA4,
                        0xA3, 0x4E, 0xB1, 0x50, 0xF7, 0x69, 0x78, 0xFA, 0x96, 0xD8, 0x28, 0x7A,
                        0xCE, 0x07, 0x2B, 0x83, 0x27, 0x04, 0x14, 0x75, 0x69, 0x4C, 0x2C, 0xBB,
                        0x25, 0x0D, 0x91, 0x79, 0x56, 0x42, 0x71, 0x73, 0x27, 0xCC, 0x8F, 0xF4,
                        0x0E, 0x2E, 0xA3, 0xC8, 0x96, 0xA3, 0x45, 0x6B, 0xA4, 0x87, 0x75, 0x4A,
                        0x0A, 0xB6, 0xB4, 0x7E, 0x82, 0xC0, 0x2E, 0xE5, 0xBC, 0x53, 0x7D, 0xE5,
                        0x32, 0xD1, 0x3C, 0x74, 0xBC, 0x6F, 0x8E, 0x1C, 0x85, 0x97, 0xFF, 0xE4,
                        0xA7, 0x64, 0xEB, 0x51, 0xCE, 0xE9, 0x4C, 0xCE, 0xF0, 0x48, 0x74, 0x91,
                        0x78, 0xC6, 0xAA, 0xBB, 0x8E, 0x72, 0x76, 0x66, 0x41, 0x4F, 0x4A, 0xA3,
                        0x41, 0xD0, 0xFE, 0x8A, 0x50, 0xCC, 0xB5, 0x99, 0x2D, 0x23, 0x70, 0xE1,
                        0x5D, 0x70, 0x0A, 0x61, 0x15, 0x79, 0x25, 0xB5, 0x62, 0x76, 0x75, 0xE8,
                        0x31, 0x3A, 0x6A, 0xBE, 0x49, 0x8E, 0xFD, 0x7B, 0xDC, 0xB6, 0x9B, 0x8F,
                        0xAE, 0xAC, 0x56, 0x4C, 0x01, 0x2C, 0xCD, 0xAF, 0xCF, 0xFD, 0x9E, 0x84,
                        0x94, 0xE0, 0x91, 0x45, 0xB3, 0x51, 0x67, 0x06, 0x8D, 0x86, 0xFB, 0x35,
                        0xA9, 0x84, 0x4A, 0x43, 0xF4, 0x75, 0xD2, 0x33, 0x62, 0x27, 0x51, 0x07,
                        0xC7, 0x9C, 0xBC, 0x6F, 0xD6, 0x1E, 0x99, 0xB4, 0xFF, 0x1F, 0x19, 0x89,
                        0x24, 0x6E, 0x33, 0xC0, 0x4C, 0xBC, 0x0F, 0x68, 0x17, 0x28, 0x3A, 0x3A,
                        0x5E, 0x61, 0xB7, 0xA4, 0x55, 0xDC, 0xE8, 0x86, 0x04, 0xE5, 0x9E, 0xF3,
                        0xF0, 0x26, 0x40, 0x2A, 0xA8, 0x07, 0xC1, 0xEC, 0xFC, 0xB7, 0x87, 0x01,
                        0x21, 0xB2, 0x2A, 0x35, 0x71, 0x8C, 0xC9, 0xA0, 0x9C, 0x83, 0x1C, 0x10,
                        0x84, 0xC4, 0x26, 0x58, 0xFA, 0xF8, 0xF3, 0x69, 0x53, 0xA9, 0x63, 0x6D,
                        0xB7, 0xC4, 0x39, 0x0C, 0x20, 0x04, 0x45, 0xB7, 0xB4, 0x52, 0x93, 0xB2,
                        0x79, 0xD5, 0xB1, 0xE3, 0x58, 0x1A, 0xBA, 0x2C, 0x36, 0x6D, 0x2C, 0x6F,
                        0x46, 0x55, 0xD7, 0x03, 0x1E, 0x01, 0x93, 0x2C, 0x49, 0x7C, 0xE7, 0x21,
                        0x23, 0x4E, 0x4B, 0x14, 0xAF, 0xDF, 0xF3, 0x4E, 0x71, 0xC2, 0xBB, 0xE9
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 20],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha1),
                    Some(0),
                );
                assert!(result);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv_crt,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha1,
                    crypto_sha1,
                    20,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 20],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha1),
                    Some(20),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pss_sha256() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 32];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha256,
                    crypto_sha256,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x1D, 0xC6, 0xAB, 0x5A, 0x35, 0x48, 0xCA, 0x40, 0x68, 0xA7, 0x7A, 0x98,
                        0x3F, 0x0F, 0x4A, 0x42, 0x00, 0xF4, 0x46, 0x31, 0x51, 0xD3, 0x90, 0x2E,
                        0xC0, 0x92, 0xFC, 0x9A, 0x04, 0xA7, 0x71, 0x80, 0xDB, 0xCA, 0x4E, 0x36,
                        0x3A, 0x71, 0xFE, 0x7B, 0xA5, 0xAB, 0x34, 0x41, 0xD3, 0x17, 0x4A, 0x3A,
                        0x96, 0xDB, 0xB7, 0xE1, 0x2F, 0xEC, 0x6F, 0x5D, 0x11, 0x40, 0x17, 0x91,
                        0x36, 0x22, 0x6F, 0x8D, 0x4C, 0x97, 0x40, 0xD8, 0x01, 0xBD, 0x3C, 0xA2,
                        0x42, 0x57, 0x52, 0xA7, 0x35, 0x2F, 0xA8, 0xD1, 0x40, 0x0F, 0x31, 0x1C,
                        0x7F, 0x28, 0xF2, 0x1B, 0x7C, 0xE1, 0x1D, 0xA9, 0xC3, 0x8E, 0x6A, 0xAD,
                        0x98, 0x31, 0xD7, 0xA9, 0x5E, 0xDC, 0x55, 0x24, 0x60, 0x72, 0xAC, 0x47,
                        0x42, 0x56, 0xCD, 0xC7, 0x77, 0x0E, 0x78, 0xA6, 0x7D, 0xA9, 0xCB, 0xA5,
                        0xF3, 0x1F, 0x65, 0xFB, 0xB6, 0x75, 0x01, 0x34, 0xD4, 0x54, 0x04, 0x0B,
                        0xC3, 0xAC, 0xB7, 0x3C, 0x90, 0x16, 0x60, 0xB8, 0xFB, 0x40, 0xFA, 0x16,
                        0x3D, 0x9A, 0x10, 0x52, 0xD5, 0x67, 0x0B, 0xF0, 0x5E, 0x1E, 0xB4, 0xFF,
                        0x6A, 0x69, 0x90, 0x06, 0x33, 0x1E, 0x36, 0xDC, 0x33, 0x26, 0x1F, 0xA3,
                        0x79, 0x83, 0xDF, 0x45, 0x0F, 0x0C, 0x91, 0x36, 0x97, 0x6C, 0x1B, 0xBB,
                        0x74, 0xCD, 0x45, 0xDB, 0x1D, 0x30, 0xE6, 0xD2, 0xE2, 0xD3, 0xFE, 0x81,
                        0x13, 0x65, 0x1E, 0x0C, 0x6F, 0x7F, 0x1A, 0xB2, 0x64, 0xA6, 0xED, 0xA0,
                        0xA6, 0xF0, 0x5E, 0x3A, 0xC8, 0xC1, 0x48, 0x5F, 0x6D, 0x6B, 0xCD, 0x28,
                        0x4C, 0xAD, 0xE4, 0x66, 0x17, 0xD2, 0x75, 0x92, 0x8A, 0x44, 0xA4, 0xC8,
                        0xBD, 0x72, 0xBA, 0x93, 0x3B, 0x75, 0x97, 0x51, 0x69, 0x76, 0x58, 0x25,
                        0x4B, 0x94, 0xA3, 0x07, 0x0D, 0x84, 0x28, 0x9A, 0x38, 0x95, 0x40, 0x63,
                        0x83, 0x08, 0xD7, 0xD6, 0x32, 0x0D, 0xFE, 0x44, 0x56, 0x36, 0x15, 0xB9,
                        0x14, 0x73, 0x3B, 0xF2, 0xF2, 0x40, 0x97, 0x8E, 0x5B, 0xAD, 0xE5, 0xFF,
                        0x48, 0xDE, 0xDF, 0xC3, 0x41, 0x13, 0x3D, 0x6E, 0x79, 0xEB, 0x6C, 0xD7,
                        0xA9, 0x1E, 0x73, 0xB6, 0xA5, 0x86, 0x9F, 0xF6, 0x44, 0x1B, 0xC4, 0xEE,
                        0x0E, 0xD2, 0xD1, 0x28, 0x19, 0xF0, 0x3E, 0x86, 0x78, 0xD6, 0x81, 0xF4,
                        0xCE, 0xB8, 0xB1, 0xFE, 0x1E, 0xB1, 0x71, 0x40, 0x70, 0x15, 0xE6, 0x9E,
                        0x3D, 0x4E, 0x60, 0xFA, 0x74, 0xAF, 0x27, 0xA3, 0xC8, 0x06, 0x48, 0x3D,
                        0xC2, 0xC9, 0xCF, 0x9A, 0xB1, 0x0D, 0xC6, 0x84, 0x7D, 0x5E, 0x38, 0xB7,
                        0xB7, 0xF6, 0x44, 0x16, 0xE7, 0x5D, 0x72, 0x5D, 0x82, 0x19, 0x64, 0x82,
                        0x01, 0xE4, 0xB1, 0x7A, 0x16, 0x45, 0xA1, 0x46, 0x93, 0x8E, 0xBE, 0x09,
                        0x10, 0x9D, 0xF8, 0x19, 0x08, 0x39, 0xA8, 0x6A, 0x3E, 0xF4, 0x98, 0x26
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 32],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha256),
                    Some(0),
                );
                assert!(result);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv_crt,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha256,
                    crypto_sha256,
                    32,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 32],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha256),
                    Some(32),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pss_sha384() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 48];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha384,
                    crypto_sha384,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x89, 0x9E, 0x06, 0x48, 0x33, 0xA9, 0xFA, 0x54, 0xE9, 0x35, 0xFC, 0x15,
                        0xD3, 0x4B, 0x73, 0x08, 0xEC, 0xE4, 0x64, 0xCD, 0x1F, 0x71, 0x09, 0x74,
                        0x16, 0x9D, 0x75, 0xDB, 0x75, 0xB2, 0x6A, 0xF9, 0x7E, 0x0A, 0x50, 0x11,
                        0x53, 0x53, 0x37, 0xB8, 0x68, 0xA9, 0xDD, 0xDE, 0x8B, 0xC7, 0x7C, 0x29,
                        0x32, 0x9D, 0xEE, 0x4B, 0x86, 0xDE, 0x86, 0x78, 0xCE, 0xFD, 0x55, 0x03,
                        0xA1, 0xE7, 0x91, 0x6A, 0x89, 0xCE, 0x2B, 0xA8, 0xC7, 0x96, 0xAC, 0xE2,
                        0x90, 0x4B, 0x72, 0xDF, 0xFD, 0x88, 0xD5, 0xB6, 0xDB, 0x62, 0x8B, 0x2F,
                        0x0C, 0xD4, 0xB1, 0x88, 0x28, 0x5B, 0x49, 0x80, 0xAA, 0xAA, 0xE3, 0x91,
                        0x65, 0xBA, 0x90, 0x3F, 0x19, 0x1A, 0x72, 0x44, 0x9E, 0x6B, 0x92, 0x97,
                        0x48, 0x20, 0xC8, 0x94, 0xB5, 0x16, 0x2E, 0x46, 0x5F, 0xD3, 0x7E, 0xB2,
                        0xD7, 0x4E, 0x9B, 0xAD, 0x0A, 0x91, 0x3D, 0x74, 0x79, 0xBF, 0x91, 0x95,
                        0xD3, 0xED, 0x46, 0x5F, 0xCC, 0xBE, 0x0C, 0x1A, 0x9C, 0x47, 0xFC, 0x97,
                        0x27, 0x40, 0x27, 0x9F, 0xCE, 0x36, 0x20, 0x3A, 0xA7, 0x65, 0x1F, 0x1C,
                        0x6D, 0x83, 0xE5, 0xCA, 0x57, 0x7C, 0x56, 0xF3, 0xB6, 0xD5, 0x55, 0xB1,
                        0x65, 0x93, 0x53, 0x18, 0xC3, 0xC5, 0x13, 0x2D, 0x60, 0xB0, 0xE4, 0xEB,
                        0xA7, 0x9B, 0xD5, 0x26, 0xFD, 0x81, 0x4E, 0x61, 0xDF, 0xBB, 0x60, 0xFC,
                        0xC9, 0x7B, 0xD6, 0xFC, 0x2D, 0x0C, 0x70, 0xC4, 0x64, 0xBA, 0xFC, 0x00,
                        0xF3, 0x2C, 0xB9, 0x9F, 0xBF, 0x49, 0x59, 0x1F, 0xD3, 0x24, 0x19, 0x5D,
                        0xB4, 0x8C, 0x02, 0xD7, 0x33, 0x17, 0x99, 0x15, 0x63, 0xA8, 0xAB, 0xB7,
                        0xC4, 0x34, 0x2D, 0x17, 0xE1, 0x45, 0x39, 0xED, 0x0A, 0xB2, 0xFE, 0xF3,
                        0x95, 0x8D, 0x33, 0x25, 0x96, 0x92, 0x9E, 0x61, 0xD2, 0x8B, 0x1F, 0x5B,
                        0x94, 0xBA, 0x87, 0xCE, 0x82, 0xFF, 0xD0, 0x7F, 0x79, 0x28, 0xB4, 0xFB,
                        0x46, 0xF9, 0xA0, 0xB2, 0xEC, 0xE4, 0x89, 0xBC, 0x58, 0x17, 0xBE, 0x06,
                        0xAE, 0xE4, 0xAB, 0xA6, 0xB3, 0xA8, 0x26, 0x9E, 0x19, 0x4A, 0xE5, 0x24,
                        0x4A, 0x4C, 0x20, 0x6E, 0x5E, 0xEB, 0xA1, 0x51, 0x0B, 0x93, 0x22, 0xE8,
                        0x6E, 0x7A, 0x65, 0xE9, 0x83, 0xF1, 0xFD, 0x64, 0xBA, 0xAA, 0x10, 0x3D,
                        0xB5, 0x6C, 0xDE, 0x16, 0x24, 0x92, 0x96, 0x79, 0x89, 0xE1, 0x4F, 0x9E,
                        0x67, 0x04, 0xED, 0xD2, 0x48, 0x9E, 0xB8, 0x59, 0x95, 0x8A, 0xD4, 0xCC,
                        0xEB, 0x76, 0x31, 0x86, 0xAB, 0x60, 0x11, 0x24, 0x8E, 0x40, 0x42, 0x73,
                        0x18, 0xF2, 0x5D, 0x45, 0x43, 0x41, 0x0B, 0xBD, 0x68, 0x29, 0xF6, 0xEC,
                        0x62, 0x5B, 0x84, 0xF4, 0x7C, 0x00, 0x63, 0x55, 0xA2, 0x64, 0x9A, 0x55,
                        0x9E, 0x02, 0x63, 0xFE, 0x7B, 0xB3, 0xC3, 0x78, 0xC1, 0x53, 0x38, 0xC2
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 48],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha384),
                    Some(0),
                );
                assert!(result);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv_crt,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha384,
                    crypto_sha384,
                    48,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 48],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha384),
                    Some(48),
                );
                assert!(result);
            }
        },
    );
}

#[test]
fn test_rsa_3k_sign_and_verify_pss_sha512() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv) =
                store_rsa_keys_no_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);
            let (_key_id_rsa3k_pub, key_id_rsa3k_priv_crt) =
                store_rsa_keys_crt(dev, session_id, DdiKeyUsage::SignVerify, 3);

            let hash = [0x1; 64];

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha512,
                    crypto_sha512,
                    0,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_no_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(
                    sig_no_crt_key,
                    [
                        0x0F, 0x66, 0x20, 0xA8, 0x01, 0x7E, 0xD5, 0xE1, 0xAB, 0x95, 0x55, 0x12,
                        0x56, 0x44, 0x65, 0x3A, 0xDC, 0x49, 0x5C, 0x68, 0x25, 0x4C, 0x38, 0x1E,
                        0x4B, 0x88, 0x9D, 0x03, 0x3A, 0x5D, 0xFA, 0xD1, 0x3A, 0x0C, 0xC8, 0xDD,
                        0x23, 0xAC, 0x22, 0x99, 0x68, 0x30, 0x09, 0xF9, 0xF5, 0xA0, 0x8D, 0x18,
                        0xEC, 0xCA, 0x46, 0xE6, 0x5B, 0x28, 0x78, 0x34, 0x0C, 0xEF, 0xE2, 0x8A,
                        0xA9, 0xE1, 0x49, 0x59, 0xE5, 0xD8, 0xBC, 0x7A, 0x7B, 0xF8, 0xA6, 0xE1,
                        0x2C, 0x08, 0xE6, 0x77, 0xE2, 0x0D, 0x6E, 0x1A, 0x8A, 0x2B, 0xE2, 0x7D,
                        0x4D, 0xD9, 0xFA, 0x93, 0xD9, 0x3F, 0x50, 0xA3, 0x2A, 0xFF, 0xAD, 0xC8,
                        0xEA, 0xEA, 0x51, 0x93, 0x4A, 0x61, 0x82, 0x76, 0xE4, 0x41, 0x7E, 0x03,
                        0x14, 0xD4, 0x34, 0xB2, 0x2D, 0x95, 0xC6, 0xBC, 0x7F, 0x0A, 0x41, 0x92,
                        0x76, 0x14, 0x07, 0x01, 0x93, 0xEA, 0x95, 0x93, 0x9A, 0xE3, 0x4C, 0x59,
                        0xD5, 0x45, 0x6E, 0xD6, 0xD7, 0x73, 0xDA, 0x84, 0xE6, 0x98, 0x42, 0x8D,
                        0x80, 0x7B, 0xB3, 0x45, 0x05, 0x1D, 0xE2, 0xC1, 0x17, 0x7D, 0x10, 0x64,
                        0xF3, 0x7C, 0xFE, 0xFE, 0x19, 0x03, 0x02, 0x3D, 0x30, 0x3F, 0xE0, 0x4E,
                        0x9C, 0x2B, 0xAA, 0x22, 0x2F, 0x81, 0x7A, 0x77, 0x84, 0x66, 0xE5, 0xDB,
                        0x84, 0x3F, 0x60, 0x45, 0xF0, 0xF3, 0xFB, 0xB1, 0xDC, 0xD4, 0x03, 0x08,
                        0xED, 0x84, 0x10, 0x22, 0x4B, 0x73, 0x11, 0xCB, 0xB6, 0x0E, 0x29, 0x81,
                        0xE1, 0xBD, 0x89, 0xE2, 0x7B, 0xF5, 0xA1, 0xB8, 0x71, 0x5E, 0x2E, 0x25,
                        0xE5, 0xBC, 0x36, 0xD2, 0x3E, 0x6F, 0x1D, 0xA3, 0xEE, 0x17, 0x3B, 0xBA,
                        0x0C, 0xF6, 0xE2, 0x47, 0x73, 0xFA, 0x49, 0xAA, 0xB3, 0xEB, 0xB1, 0x20,
                        0x22, 0xAF, 0x67, 0xA3, 0x68, 0x77, 0xDA, 0x7D, 0xE7, 0xF0, 0x83, 0xF4,
                        0xA1, 0xB4, 0x27, 0x57, 0x09, 0xA5, 0x0C, 0x84, 0xEC, 0xA3, 0x42, 0x20,
                        0xF0, 0xF7, 0x7C, 0x64, 0xF9, 0xC6, 0xEF, 0xFF, 0xEC, 0x98, 0x22, 0x6C,
                        0x31, 0xDA, 0xB3, 0xDB, 0x7F, 0xFF, 0xC5, 0x02, 0x75, 0x26, 0x4E, 0xD8,
                        0xDA, 0xC5, 0x2E, 0xAD, 0x2D, 0x57, 0x13, 0x7E, 0xA4, 0xD5, 0xBE, 0xE9,
                        0xE3, 0x54, 0x03, 0xBA, 0x88, 0x05, 0xB8, 0xFF, 0x75, 0x74, 0x41, 0x91,
                        0x0B, 0xFA, 0x94, 0x84, 0x83, 0xED, 0xB8, 0x87, 0x53, 0xB0, 0x8D, 0x00,
                        0xFA, 0xCA, 0x03, 0x34, 0x7D, 0xA1, 0x20, 0x6F, 0xBC, 0x16, 0x1C, 0xAF,
                        0xF4, 0xA7, 0x22, 0xDE, 0xF0, 0xCD, 0x71, 0x9F, 0x48, 0x89, 0x36, 0x47,
                        0xA6, 0x2C, 0x5A, 0x96, 0xF5, 0x6B, 0xCC, 0x35, 0x11, 0x20, 0x25, 0x61,
                        0xE6, 0x4F, 0x9D, 0x3A, 0x7F, 0xC9, 0x2C, 0xEC, 0x50, 0x91, 0x11, 0x33,
                        0xE1, 0x81, 0x6F, 0x94, 0xD4, 0xF5, 0xAD, 0x2C, 0x18, 0xCE, 0x97, 0x26
                    ]
                );

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 64],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha512),
                    Some(0),
                );
                assert!(result);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv_crt,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let sig_crt_key = &resp.data.x.data()[..resp.data.x.len()];

                assert_eq!(sig_no_crt_key, sig_crt_key);
            }

            {
                let padded_hash = RsaEncoding::encode_pss(
                    &hash,
                    3072 - 1,
                    RsaDigestKind::Sha512,
                    crypto_sha512,
                    64,
                    |buf| rand_bytes(buf).map_err(|_| ()),
                )
                .unwrap();

                let mut y = [0u8; 512];
                y[..padded_hash.len()].copy_from_slice(&padded_hash);

                let req = DdiRsaModExpCmdReq {
                    hdr: DdiReqHdr {
                        op: DdiOp::RsaModExp,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: key_id_rsa3k_priv,
                        y: MborByteArray::new(y, padded_hash.len())
                            .expect("failed to create byte array"),
                        op_type: DdiRsaOpType::Sign,
                    },
                    ext: None,
                };
                let mut cookie = None;
                let resp = dev.exec_op(&req, &mut cookie);
                assert!(resp.is_ok(), "resp {:?}", resp);
                let resp = resp.unwrap();

                let result = rsa_verify_local_openssl(
                    &TEST_RSA_3K_PUBLIC_KEY,
                    &resp.data.x.data()[..resp.data.x.len()],
                    &[0x1; 64],
                    CryptoRsaSignaturePadding::Pss,
                    Some(DdiHashAlgorithm::Sha512),
                    Some(64),
                );
                assert!(result);
            }
        },
    );
}
