// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EccGenerateKeyPair smoke tests for the emu backend.
//!
//! - Happy path: generate a P-256/384/521 sign/verify key in an open
//!   session and confirm the response carries a non-zero
//!   `private_key_id`, a non-empty public key, and a populated
//!   masked-key envelope (randomized IV).
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
            // Every curve must generate cleanly and return a non-empty
            // public key plus a populated masked-key envelope.
            for curve in [DdiEccCurve::P256, DdiEccCurve::P384, DdiEccCurve::P521] {
                let key_props =
                    helper_key_properties(DdiKeyUsage::SignVerify, DdiKeyAvailability::App);
                let resp = helper_ecc_generate_key_pair(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    curve,
                    None,
                    key_props,
                )
                .unwrap();

                assert_eq!(resp.hdr.op, DdiOp::EccGenerateKeyPair);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_ne!(
                    resp.data.private_key_id, 0,
                    "private_key_id must be non-zero for {curve:?}",
                );
                assert!(
                    !resp.data.pub_key.der.as_slice().is_empty(),
                    "public key bytes must be non-empty for {curve:?}",
                );

                // The generated private key is returned as a populated
                // masked-key envelope with a randomized IV.
                assert!(
                    !resp.data.masked_key.as_slice().is_empty(),
                    "masked_key must be populated for {curve:?}",
                );
                assert!(
                    verify_iv_not_default_from_masked_key(resp.data.masked_key.as_slice())
                        .unwrap_or(false),
                    "masked_key IV must be randomized for {curve:?}",
                );
                assert!(
                    verify_masked_key_attributes(
                        resp.data.masked_key.as_slice(),
                        MaskedKeyAttributes::SIGN | MaskedKeyAttributes::VERIFY
                    ),
                    "masked_key attributes must include SIGN|VERIFY for {curve:?}",
                );
            }
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
