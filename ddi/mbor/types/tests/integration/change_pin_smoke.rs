// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ChangePin smoke tests for the emu backend.
//!
//! Exercises the ChangePin firmware command end-to-end from the host
//! side within an open session:
//!
//! - Happy path: ECDH + HKDF + HMAC verify + AES-CBC decrypt succeed
//!   and the partition credential's PIN is replaced (`Success`); after
//!   the change a fresh OpenSession with the *old* PIN is rejected
//!   (`InvalidAppCredentials`) while the *new* PIN succeeds.
//! - Tampered ciphertext: a flipped byte in the encrypted PIN fails the
//!   `enc_pin ‖ iv ‖ nonce` HMAC check and is rejected with
//!   `PinDecryptionFailed`, leaving the credential unchanged.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Attempts to open a fresh session with the given user id / PIN and
/// returns the result, so a caller can assert the credential is (or is
/// no longer) accepted.
fn try_open_session_with_pin(
    ddi: &DdiTest,
    path: &str,
    id: [u8; 16],
    pin: [u8; 16],
) -> Result<DdiOpenSessionCmdResp, DdiError> {
    let login_dev = ddi.open_dev(path).unwrap();
    let (encrypted_credential, pub_key) =
        encrypt_userid_pin_for_open_session(&login_dev, id, pin, TEST_SESSION_SEED);
    helper_open_session(
        &login_dev,
        None,
        Some(DdiApiRev { major: 1, minor: 0 }),
        encrypted_credential,
        pub_key,
    )
}

#[test]
fn test_change_pin_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let (new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            let resp = helper_change_pin(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_pin,
                pub_key,
            )
            .expect("ChangePin happy path must succeed");

            assert_eq!(resp.hdr.op, DdiOp::ChangePin);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(
                resp.hdr.sess_id,
                Some(session_id),
                "ChangePin response must echo the session id"
            );

            // The old PIN must no longer authenticate a new session.
            let old_pin_result = try_open_session_with_pin(ddi, path, TEST_CRED_ID, TEST_CRED_PIN);
            assert!(
                matches!(
                    old_pin_result,
                    Err(DdiError::DdiStatus(DdiStatus::InvalidAppCredentials))
                ),
                "OpenSession with the old PIN must be rejected after ChangePin, got {:?}",
                old_pin_result
            );

            // The new PIN must authenticate a new session.
            let new_pin_result =
                try_open_session_with_pin(ddi, path, TEST_CRED_ID, TEST_CRED_PIN_ALT);
            assert!(
                new_pin_result.is_ok(),
                "OpenSession with the new PIN must succeed after ChangePin, got {:?}",
                new_pin_result
            );
        },
    );
}

#[test]
fn test_change_pin_tampered_pin_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let (mut new_pin, pub_key) = encrypt_pin_for_change_pin(dev, TEST_CRED_PIN_ALT);

            // Flip a ciphertext byte so the authenticated
            // `enc_pin ‖ iv ‖ nonce` HMAC no longer matches the tag.
            new_pin.encrypted_pin.data_mut()[10] = new_pin.encrypted_pin.data()[10].wrapping_add(1);

            let err = helper_change_pin(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                new_pin,
                pub_key,
            )
            .expect_err("tampered PIN must be rejected");

            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::PinDecryptionFailed)),
                "expected PinDecryptionFailed, got {:?}",
                err
            );
        },
    );
}
