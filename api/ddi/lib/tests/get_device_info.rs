// Copyright (C) Microsoft Corporation. All rights reserved.

mod common;

use mcr_ddi::*;
use mcr_ddi_types::*;
use test_with_tracing::test;

use crate::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id
    25
}

#[test]
fn test_get_device_info() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let req = DdiGetDeviceInfoCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetDeviceInfo,
                    sess_id: None,
                    rev: Some(DdiApiRev { major: 1, minor: 0 }),
                },
                data: DdiGetDeviceInfoReq {},
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie).unwrap();
            assert_eq!(resp.hdr.op, DdiOp::GetDeviceInfo);
            assert!(resp.hdr.rev.is_some());
            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.status, DdiStatus::Success);
        },
    );
}

#[test]
fn test_get_device_info_with_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            let _ = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) =
                encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let app_dev = open_dev_and_set_device_kind(ddi, path);

            let resp = helper_open_session(
                &app_dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            let req = DdiGetDeviceInfoCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetDeviceInfo,
                    sess_id: Some(resp.data.sess_id),
                    rev: None,
                },
                data: DdiGetDeviceInfoReq {},
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
fn test_get_device_info_with_invalid_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let req = DdiGetDeviceInfoCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetDeviceInfo,
                    sess_id: Some(0x50),
                    rev: None,
                },
                data: DdiGetDeviceInfoReq {},
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
fn test_get_device_info_with_invalid_rev() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let req = DdiGetDeviceInfoCmdReq {
                hdr: DdiReqHdr {
                    op: DdiOp::GetDeviceInfo,
                    sess_id: None,
                    rev: Some(DdiApiRev {
                        major: 10,
                        minor: 0,
                    }),
                },
                data: DdiGetDeviceInfoReq {},
                ext: None,
            };
            let mut cookie = None;
            let resp = dev.exec_op(&req, &mut cookie);
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
            ));
        },
    );
}
