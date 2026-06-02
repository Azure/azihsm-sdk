// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetSessionEncryptionKey smoke tests for the emu backend.
//!
//! Exercises the GetSessionEncryptionKey firmware command from the
//! host side end-to-end:
//!
//! - Happy path: after a credential has been established, the command
//!   returns a non-empty session encryption public key, a non-empty
//!   nonce, and a non-empty signature over the public key.
//! - Before establishment: the command is rejected with
//!   `CredentialsNotEstablished` (the host has no use for a session
//!   encryption key without a credential to wrap into `OpenSession`).

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // GetSessionEncryptionKey is a no-session command; the harness
    // ignores the returned id so any sentinel value is fine.
    0
}

#[test]
fn test_get_session_encryption_key_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let resp =
            helper_get_session_encryption_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }))
                .unwrap();

        assert!(resp.hdr.sess_id.is_none());
        assert_eq!(resp.hdr.op, DdiOp::GetSessionEncryptionKey);
        assert_eq!(resp.hdr.status, DdiStatus::Success);

        assert!(
            !resp.data.pub_key.der.is_empty(),
            "session encryption pub_key must be non-empty"
        );
        assert!(
            !resp.data.nonce.is_empty(),
            "session encryption nonce must be non-empty"
        );

        // The signature is only populated by real or emulated devices;
        // the mock dispatcher returns an empty placeholder.
        if get_device_kind(dev) != DdiDeviceKind::Virtual {
            assert!(
                !resp.data.pub_key_signature.is_empty(),
                "session encryption pub_key_signature must be non-empty"
            );
        }
    });
}

#[test]
fn test_get_session_encryption_key_without_establish_cred_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        let err =
            helper_get_session_encryption_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }))
                .expect_err("must be rejected before EstablishCredential");

        assert!(
            matches!(
                err,
                DdiError::DdiStatus(DdiStatus::CredentialsNotEstablished)
            ),
            "expected CredentialsNotEstablished, got {:?}",
            err
        );
    });
}
