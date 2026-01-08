// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // Return incorrect session id since this is a no session command
    25
}

#[test]
fn test_open_session_simple() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            let sess_id = resp.data.sess_id;
            let resp =
                helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }));

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_open_session_simple_repeat() {
    ddi_dev_test(
        setup,
        common_cleanup,
        |dev, _ddi, _path, _incorrect_session_id| {
            helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                TEST_SESSION_SEED,
            );

            let resp = helper_open_session(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = resp.unwrap();

            assert!(resp.hdr.sess_id.is_some());
            assert_eq!(resp.hdr.op, DdiOp::OpenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);

            let sess_id = resp.data.sess_id;

            let resp =
                helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }));

            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_close_session_no_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let resp = helper_close_session(dev, None, Some(DdiApiRev { major: 1, minor: 0 }));

            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ));
        },
    );
}

#[test]
fn test_close_session_incorrect_session_id() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let session_id = 20;
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
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
fn test_close_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}

#[test]
fn test_close_session_multiple() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_err(), "resp {:?}", resp);

            assert!(matches!(
                resp.unwrap_err(),
                DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession)
            ));
        },
    );
}

#[test]
fn test_close_session_middle_session() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let max_sessions = MAX_SESSIONS;

            let mut file_handles: Vec<Option<<DdiTest as Ddi>::Dev>> = Vec::new();
            for _ in 0..max_sessions - 1 {
                file_handles.push(None);
            }

            let _ = helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN);

            let mut opened_sessions = Vec::<u16>::new();

            for element in file_handles.iter_mut() {
                *element = Some(open_dev_and_set_device_kind(ddi, path));

                if let Some(file_handle) = element {
                    let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                        file_handle,
                        TEST_CRED_ID,
                        TEST_CRED_PIN,
                        TEST_SESSION_SEED,
                    );

                    let resp = helper_open_session(
                        file_handle,
                        None,
                        Some(DdiApiRev { major: 1, minor: 0 }),
                        encrypted_credential,
                        pub_key,
                    );
                    assert!(resp.is_ok(), "resp {:?}", resp);

                    let resp = resp.unwrap();

                    opened_sessions.push(resp.data.sess_id);
                }
            }

            let session_to_close = opened_sessions[max_sessions / 2];
            if let Some(file_handle) = &file_handles[max_sessions / 2] {
                let resp = helper_close_session(
                    file_handle,
                    Some(session_to_close),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                );

                assert!(resp.is_ok(), "resp {:?}", resp);
            }

            if let Some(file_handle) = &file_handles[max_sessions / 2] {
                let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                    file_handle,
                    TEST_CRED_ID,
                    TEST_CRED_PIN,
                    TEST_SESSION_SEED,
                );

                let resp = helper_open_session(
                    file_handle,
                    None,
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    encrypted_credential,
                    pub_key,
                );
                assert!(resp.is_ok(), "resp {:?}", resp);
            }
        },
    );
}

#[test]
fn test_close_session_after_lm() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let result = dev.simulate_nssr_after_lm();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let resp = helper_close_session(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            );
            assert!(resp.is_ok(), "resp {:?}", resp);
        },
    );
}
