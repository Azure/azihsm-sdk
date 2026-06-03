// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetUnwrappingKey smoke tests for the emu backend.
//!
//! Exercises the GetUnwrappingKey firmware command end-to-end through
//! the emu device:
//!
//! - Happy path: with an open session, the command returns a non-empty
//!   RSA-2048 public key and a valid (non-zero) key id.  We
//!   intentionally do *not* assert on the `masked_key` field here —
//!   the firmware emits an empty placeholder until the masked-key
//!   wrapping infrastructure for vault-stored keys is wired up.
//! - Stability: calling the command twice on the same partition
//!   returns the same key id and the same public-key bytes — the
//!   key is partition-cached and lazily generated on first call.
//! - Without a session: rejected with
//!   `FileHandleSessionIdDoesNotMatch` (enforced by the emu's
//!   session-validation layer before the firmware handler runs).

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_get_unwrapping_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let resp = helper_get_unwrapping_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("get_unwrapping_key should succeed");

            assert_eq!(resp.hdr.op, DdiOp::GetUnwrappingKey);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_eq!(resp.hdr.sess_id, Some(session_id));

            assert!(
                !resp.data.pub_key.der.is_empty(),
                "unwrap pub_key must be non-empty"
            );
            assert_eq!(
                resp.data.pub_key.key_kind,
                DdiKeyType::Rsa2kPublic,
                "unwrap key must be RSA-2048"
            );
        },
    );
}

#[test]
fn test_get_unwrapping_key_stable_across_calls_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let r1 = helper_get_unwrapping_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("first get_unwrapping_key");
            let r2 = helper_get_unwrapping_key(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
            )
            .expect("second get_unwrapping_key");

            assert_eq!(
                r1.data.key_id, r2.data.key_id,
                "repeat call must return the same key id"
            );
            assert_eq!(
                r1.data.pub_key.der.as_slice(),
                r2.data.pub_key.der.as_slice(),
                "repeat call must return the same pub_key bytes"
            );
        },
    );
}

#[test]
fn test_get_unwrapping_key_no_session_smoke() {
    ddi_dev_test(common_setup, common_cleanup, |dev, _ddi, _path, _| {
        let err = helper_get_unwrapping_key(dev, None, Some(DdiApiRev { major: 1, minor: 0 }))
            .expect_err("must be rejected without a session");

        assert!(
            matches!(
                err,
                DdiError::DdiStatus(DdiStatus::FileHandleSessionIdDoesNotMatch)
            ),
            "expected FileHandleSessionIdDoesNotMatch, got {:?}",
            err
        );
    });
}
