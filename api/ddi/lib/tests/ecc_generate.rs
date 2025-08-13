// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_mbor::MborByteArray;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

#[test]
fn test_ecc_generate_malformed_ddi() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Make the header have the opcode but body of different type
            {
                let resp = helper_get_api_rev_op(
                    dev,
                    DdiOp::EccGenerateKeyPair,
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
                        op: DdiOp::EccGenerateKeyPair,
                        sess_id: Some(session_id),
                        rev: Some(DdiApiRev { major: 1, minor: 0 }),
                    },
                    data: DdiRsaModExpReq {
                        key_id: 0x1,
                        y: MborByteArray::new([1u8; 512], 32).expect("failed to create byte array"),
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
fn test_ecc_generate_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
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
fn test_ecc_generate_invalid_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(20),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
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
fn test_ecc_generate_invalid_key_usage() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);

            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_err(), "resp {:?}", resp);
            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidPermissions)
            ));
        },
    );
}

#[test]
fn test_ecc_generate_session_only_key_with_key_tag() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let mut session_only_key_dev = ddi.open_dev(path).unwrap();
            set_device_kind(&mut session_only_key_dev);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &session_only_key_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
            );

            let resp = helper_open_session(
                &session_only_key_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let session_only_key_session = resp.hdr.sess_id;

            let key_props =
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

            let resp = helper_ecc_generate_key_pair(
                &session_only_key_dev,
                session_only_key_session,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
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
fn test_ecc_generate_session_only_key() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |_dev, ddi, path, _session_id| {
            let mut session_only_key_dev = ddi.open_dev(path).unwrap();
            set_device_kind(&mut session_only_key_dev);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                &session_only_key_dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
            );

            let resp = helper_open_session(
                &session_only_key_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let session_only_key_session = resp.hdr.sess_id;

            let key_props =
                helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::Session);

            let resp = helper_ecc_generate_key_pair(
                &session_only_key_dev,
                session_only_key_session,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            );

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_ecc_generate() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

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

                assert!(resp.data.pub_key.is_some());
            }

            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P384,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.data.pub_key.is_some());
            }

            {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);

                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P521,
                    None,
                    key_props,
                );

                assert!(resp.is_ok(), "resp {:?}", resp);

                let resp = resp.unwrap();

                assert!(resp.data.pub_key.is_some());
            }
        },
    );
}
