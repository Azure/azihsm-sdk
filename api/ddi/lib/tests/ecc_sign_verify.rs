// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecc_sign_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let digest = [1u8; 96];
            let digest_len = 20;

            let req = DdiEccSignCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::EccSign,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiEccSignReq {
                    key_id: private_key_id,
                    digest: MborByteArray::new(digest, digest_len)
                        .expect("failed to create byte array"),
                    digest_algo: DdiHashAlgorithm::Sha256,
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
fn test_ecc_sign_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let digest = [1u8; 96];
            let digest_len = 20;

            let req = DdiEccSignCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::EccSign,
                    sess_id: Some(20),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiEccSignReq {
                    key_id: private_key_id,
                    digest: MborByteArray::new(digest, digest_len)
                        .expect("failed to create byte array"),
                    digest_algo: DdiHashAlgorithm::Sha256,
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
fn test_ecc_sign_incorrect_key_type() {
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

            let resp = resp.unwrap();

            let digest = [1u8; 96];
            let digest_len = 20;

            let req = DdiEccSignCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::EccSign,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiEccSignReq {
                    key_id: resp.data.key_id,
                    digest: MborByteArray::new(digest, digest_len)
                        .expect("failed to create byte array"),
                    digest_algo: DdiHashAlgorithm::Sha256,
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
fn test_ecc_sign_incorrect_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (private_key_id, _pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::Derive);

            let digest = [1u8; 96];
            let digest_len = 20;

            let req = DdiEccSignCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::EccSign,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiEccSignReq {
                    key_id: private_key_id,
                    digest: MborByteArray::new(digest, digest_len)
                        .expect("failed to create byte array"),
                    digest_algo: DdiHashAlgorithm::Sha256,
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
fn test_ecc_sign_verify() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (private_key_id, pub_key) =
                ecc_gen_key_mcr(dev, DdiEccCurve::P256, session_id, DdiKeyUsage::SignVerify);

            let digest = [1u8; 96];
            let digest_len = 20;

            let req = DdiEccSignCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::EccSign,
                    sess_id: Some(session_id),
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiEccSignReq {
                    key_id: private_key_id,
                    digest: MborByteArray::new(digest, digest_len)
                        .expect("failed to create byte array"),
                    digest_algo: DdiHashAlgorithm::Sha256,
                },
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);

            assert!(resp.is_ok(), "resp {:?}", resp);
            let resp = resp.unwrap();

            let signature_len = resp.data.signature.len();

            // Should return true
            assert!(ecc_verify_local_openssl(
                &resp.data.signature.data()[..signature_len],
                &pub_key,
                digest,
                digest_len
            ));

            let mut tampered_digest = digest;
            tampered_digest[0] = tampered_digest[0].wrapping_add(0x1);

            // Should return false
            assert!(!ecc_verify_local_openssl(
                &resp.data.signature.data()[..signature_len],
                &pub_key,
                tampered_digest,
                digest_len
            ));
        },
    );
}
