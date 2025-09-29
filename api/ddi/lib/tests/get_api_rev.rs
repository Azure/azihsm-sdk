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
fn test_api_rev() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let resp = helper_get_api_rev(dev, None, None).unwrap();

            assert_eq!(resp.hdr.op, DdiOp::GetApiRev);
            assert!(resp.hdr.rev.is_none());
            assert!(resp.hdr.sess_id.is_none());
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            assert!(resp.data.min.major <= resp.data.max.major);

            if resp.data.min.major == resp.data.max.major {
                assert!(resp.data.min.minor <= resp.data.max.minor);
            }

            assert_eq!(resp.data.min.major, 1);
            assert_eq!(resp.data.min.minor, 0);
            assert_eq!(resp.data.max.major, 1);
            assert_eq!(resp.data.max.minor, 0);
        },
    );
}

#[test]
fn test_api_rev_with_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, ddi, path, _incorrect_session_id| {
            let _ = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

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

            let resp = helper_get_api_rev(dev, Some(resp.data.sess_id), None);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_api_rev_with_invalid_session() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let resp = helper_get_api_rev(dev, Some(0x50), None);

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::InvalidArg)
            ));
        },
    );
}

#[test]
fn test_api_rev_with_invalid_rev() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            let resp = helper_get_api_rev(dev, None, Some(DdiApiRev { major: 1, minor: 0 }));

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::UnsupportedRevision)
            ));
        },
    );
}
