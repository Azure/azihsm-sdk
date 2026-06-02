// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! OpenSession smoke tests for the emu backend.
//!
//! Exercises the OpenSession firmware command from the host side
//! end-to-end:
//!
//! - Happy path: after a credential has been established, OpenSession
//!   returns a `Some` session id, `Success` status, and a non-empty
//!   `bmk_session` blob.
//! - With a mismatched session credential (incorrect id or pin):
//!   rejected with `InvalidAppCredentials`.
//! - Before credential establishment: rejected with
//!   `CredentialsNotEstablished` — firmware fails fast on the missing
//!   credential before inspecting the encrypted payload.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

pub fn setup(dev: &mut <DdiTest as Ddi>::Dev, ddi: &DdiTest, path: &str) -> u16 {
    common_cleanup(dev, ddi, path, None);

    // OpenSession is classified `SessionCtrl::Open`; the harness
    // expects a sentinel session id but does not assert on it.
    0
}

#[test]
fn test_open_session_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
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
        )
        .unwrap();

        assert_eq!(resp.hdr.op, DdiOp::OpenSession);
        assert_eq!(resp.hdr.status, DdiStatus::Success);
        assert!(
            resp.hdr.sess_id.is_some(),
            "OpenSession response header must carry the new sess_id"
        );
        assert!(
            !resp.data.bmk_session.is_empty(),
            "OpenSession response must carry a non-empty bmk_session"
        );
    });
}

#[test]
fn test_open_session_incorrect_id_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(dev, [1; 16], TEST_CRED_PIN, TEST_SESSION_SEED);

        let err = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )
        .expect_err("OpenSession must reject a session credential with the wrong id");

        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)),
            "expected InvalidAppCredentials, got {:?}",
            err
        );
    });
}

#[test]
fn test_open_session_incorrect_pin_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        helper_common_establish_credential(dev, TEST_CRED_ID, TEST_CRED_PIN);

        let (encrypted_credential, pub_key) =
            encrypt_userid_pin_for_open_session(dev, TEST_CRED_ID, [1; 16], TEST_SESSION_SEED);

        let err = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )
        .expect_err("OpenSession must reject a session credential with the wrong pin");

        assert!(
            matches!(err, DdiError::DdiStatus(DdiStatus::InvalidAppCredentials)),
            "expected InvalidAppCredentials, got {:?}",
            err
        );
    });
}

#[test]
fn test_open_session_without_establish_cred_smoke() {
    ddi_dev_test(setup, common_cleanup, |dev, _ddi, _path, _| {
        // Without an established credential we cannot call
        // `encrypt_userid_pin_for_open_session` (it internally calls
        // `GetSessionEncryptionKey` which itself requires a
        // credential), so build a placeholder payload by hand.  The
        // bytes only need to satisfy host-side MBOR length invariants;
        // firmware must fail fast on the missing credential before
        // inspecting any of them.
        let (encrypted_credential, pub_key) = build_placeholder_open_session_inputs();

        let err = helper_open_session(
            dev,
            None,
            Some(DdiApiRev { major: 1, minor: 0 }),
            encrypted_credential,
            pub_key,
        )
        .expect_err("OpenSession must be rejected before EstablishCredential");

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

/// Build an OpenSession request body that the host MBOR codec will
/// accept (correct field lengths and a wire-valid `DdiDerPublicKey`),
/// for use by tests that exercise pre-crypto fail-fast paths.
///
/// The `pub_key` is a known-good 120-byte SPKI-DER encoding of a P-384
/// public key; it is copied from
/// [`super::open_session::test_open_session_without_get_key`] so both
/// the smoke and the long-form negative test share the same placeholder
/// and any future format change updates both at once.
fn build_placeholder_open_session_inputs() -> (DdiEncryptedSessionCredential, DdiDerPublicKey) {
    let encrypted_credential = DdiEncryptedSessionCredential {
        encrypted_id: MborByteArray::from_slice(&[0u8; 16]).unwrap(),
        encrypted_pin: MborByteArray::from_slice(&[0u8; 16]).unwrap(),
        encrypted_seed: MborByteArray::from_slice(&[0u8; 48]).unwrap(),
        iv: MborByteArray::from_slice(&[0u8; 16]).unwrap(),
        nonce: [0u8; 32],
        tag: [0u8; 48],
    };
    let pub_key = DdiDerPublicKey {
        der: MborByteArray::from_slice(&[
            0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xe4, 0x20, 0x9a, 0xd7,
            0x07, 0xa4, 0x88, 0x1a, 0xff, 0xf0, 0x12, 0x61, 0x92, 0xc7, 0x9d, 0x83, 0x77, 0x49,
            0x21, 0xcc, 0x5d, 0xf3, 0xb9, 0x21, 0xc4, 0x3d, 0xae, 0xaa, 0x58, 0xb8, 0x34, 0x2b,
            0x38, 0x3c, 0xda, 0xb2, 0x88, 0xf0, 0xe4, 0xb9, 0x56, 0x14, 0x11, 0x15, 0x75, 0xba,
            0xbb, 0x23, 0x7c, 0x67, 0xf7, 0xd1, 0x97, 0x63, 0xc7, 0xb8, 0x56, 0xd3, 0x22, 0xb2,
            0xba, 0xba, 0x1a, 0xc6, 0xb4, 0xea, 0x0d, 0xad, 0xa2, 0x56, 0x29, 0xd5, 0xca, 0x0f,
            0x4a, 0x4e, 0xee, 0x17, 0xb0, 0xb2, 0xf4, 0xb1, 0x58, 0xba, 0xae, 0xa1, 0x58, 0x9c,
            0x10, 0x07, 0xf7, 0x0e, 0xc7, 0x62, 0x42, 0xe0,
        ])
        .expect("placeholder pub_key DER must fit MborByteArray"),
        key_kind: DdiKeyType::Ecc384Public,
    };
    (encrypted_credential, pub_key)
}
