// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ReopenSession smoke tests for the emu backend.
//!
//! Exercises the ReopenSession firmware command end-to-end after a
//! simulated live-migration NSSR:
//!
//! - Happy path: after the NSSR the credential is re-established and the
//!   migrated session is reopened under the same id by unmasking the
//!   host-persisted `bmk_session` and re-keying the preserved
//!   (renegotiation-pending) slot (`Success`).
//! - Wrong PIN: reopening with a credential whose PIN does not match the
//!   partition credential is rejected, leaving the slot unusable.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_reopen_session_smoke() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            // Simulate the live-migration NSSR.
            let result = dev.erase();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            // Re-establish the partition credential (no unwrapping-key
            // re-import) so the reopen can authenticate.
            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            )
            .expect("ReopenSession happy path must succeed");

            assert_eq!(resp.hdr.op, DdiOp::ReopenSession);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(
                resp.data.sess_id, setup_res.session_id,
                "ReopenSession must reuse the migrated session id"
            );
            assert!(
                !resp.data.bmk_session.is_empty(),
                "ReopenSession must return a re-enveloped session masking key"
            );
        },
    );
}

#[test]
fn test_reopen_session_incorrect_pin_smoke() {
    ddi_dev_test(
        |_, _, _| 0,
        common_cleanup,
        |dev, ddi, path, _session_id| {
            let setup_res = common_setup_for_lm(dev, ddi, path);

            let result = dev.erase();
            assert!(
                result.is_ok(),
                "Migration simulation should succeed: {:?}",
                result
            );

            let _ = helper_common_establish_credential_with_bmk(
                dev,
                TEST_CRED_ID,
                TEST_CRED_PIN,
                setup_res.masked_bk3,
                setup_res.partition_bmk,
                MborByteArray::from_slice(&[])
                    .expect("Failed to create empty masked unwrapping key"),
            );

            // Reopen with a PIN that does not match the partition credential.
            let (encrypted_credential, pub_key) = encrypt_userid_pin_for_open_session(
                dev,
                TEST_CRED_ID,
                [1; 16],
                setup_res.random_seed,
            );

            let resp = helper_reopen_session(
                dev,
                setup_res.session_id,
                Some(DdiApiRev { major: 1, minor: 0 }),
                encrypted_credential,
                pub_key,
                setup_res.session_bmk,
            );

            assert!(
                resp.is_err(),
                "ReopenSession with an incorrect PIN must be rejected, got {:?}",
                resp
            );
        },
    );
}
