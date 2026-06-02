// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CloseSession smoke tests for the emu backend.
//!
//! Exercises the CloseSession firmware command from the host side
//! end-to-end:
//!
//! - Happy path: after OpenSession returns a fresh `sess_id`,
//!   CloseSession against that id succeeds and echoes the id back in
//!   the response header.
//! - Double-close: after a successful CloseSession, a second
//!   CloseSession against the same id is rejected (the host-side
//!   `dev` no longer tracks the session, so the request is rejected
//!   with `FileHandleNoExistingSession` before reaching firmware).

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // CloseSession is classified `SessionCtrl::Close`; the harness
    // expects a sentinel session id but does not assert on it.
    0
}

#[test]
fn test_close_session_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        let sess_id = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )
        .unwrap()
        .data
        .sess_id;

        let resp = helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }))
            .unwrap();

        assert_eq!(resp.hdr.op, DdiOp::CloseSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        assert_eq!(
            resp.hdr.sess_id,
            Some(sess_id),
            "CloseSession response must echo the closed sess_id"
        );
    });
}

#[test]
fn test_close_session_twice_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
            dev,
            TEST_CRED_ID,
            TEST_CRED_PIN,
            TEST_SESSION_SEED,
        );

        let sess_id = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )
        .unwrap()
        .data
        .sess_id;

        helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }))
            .expect("first CloseSession must succeed");

        let err = helper_close_session(dev, Some(sess_id), Some(DdiApiRev { major: 1, minor: 0 }))
            .expect_err("second CloseSession against the same id must be rejected");

        assert!(
            matches!(
                err,
                DdiError::DdiStatus(DdiStatus::FileHandleNoExistingSession)
            ),
            "expected FileHandleNoExistingSession, got {:?}",
            err
        );
    });
}
