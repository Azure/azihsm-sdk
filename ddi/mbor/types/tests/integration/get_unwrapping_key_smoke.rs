// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! GetUnwrappingKey smoke tests.
//!
//! - Happy path: with an open session, the command returns an RSA-2048
//!   public key and a vault key id.  We intentionally do *not* assert
//!   on `masked_key` — the firmware emits an empty placeholder until
//!   vault-key masking is wired up — nor on the exact `key_id` value,
//!   which is an opaque handle (the sim backend legitimately assigns
//!   `0`).
//! - Stability: two calls on the same partition return the same key id
//!   and public-key bytes — the key is partition-cached and lazily
//!   generated on first use.
//! - Without a session: rejected with `FileHandleSessionIdDoesNotMatch`
//!   by the host-side dev validator before the request reaches firmware.

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
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
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
        },
    );
}
