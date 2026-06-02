// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EccGenerateKeyPair smoke tests for the emu backend.
//!
//! - Happy path: generate a P-256 sign/verify key in an open session
//!   and confirm the response carries a non-zero `private_key_id`
//!   and a non-empty public key.
//! - Without a session: rejected by the host-side dev validator
//!   before the request reaches firmware.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_test_helpers::helper_key_properties;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_ecc_generate_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let resp = helper_ecc_generate_key_pair(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            )
            .unwrap();

            assert_eq!(resp.hdr.op, DdiOp::EccGenerateKeyPair);
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert_ne!(
                resp.data.private_key_id, 0,
                "private_key_id must be non-zero"
            );
            assert!(
                !resp.data.pub_key.der.as_slice().is_empty(),
                "public key bytes must be non-empty"
            );
        },
    );
}

#[test]
fn test_ecc_generate_no_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props = helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
            let err = helper_ecc_generate_key_pair(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
                key_props,
            )
            .expect_err("EccGenerateKeyPair must be rejected without a session");

            // The host-side dev validator rejects InSession commands sent
            // with sess_id=None before the request reaches firmware.
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
