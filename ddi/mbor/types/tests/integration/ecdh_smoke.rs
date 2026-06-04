// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! EcdhKeyExchange smoke tests for the emu backend.
//!
//! - Happy path: generate two P-256 ECC keypairs in the open
//!   session, derive a shared secret from each side, and assert both
//!   ECDH calls succeed (so the derived `Secret256` vault entry is
//!   created).
//! - Reject ECDH against an unknown private key id: the backend
//!   returns `KeyNotFound` (emu) or `InvalidKeyNumber` (mock); both
//!   are acceptable.
//! - Reject ECDH where the requested target `key_type` does not
//!   match the private key's curve.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_test_helpers::*;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_ecdh_key_exchange_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate two P-256 derive-capable keypairs in the open
            // session.  Each side holds its own private key and
            // receives the peer's public key.
            let (priv_key_id1, pub_key1, pub_key1_len, priv_key_id2, pub_key2, pub_key2_len) =
                helper_create_ecc_key_pairs(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P256,
                    None,
                );

            // Side A: derive Secret256 from (priv1, pub2).
            let resp1 = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret256,
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App),
            )
            .unwrap();
            assert_eq!(resp1.hdr.op, DdiOp::EcdhKeyExchange);
            assert_eq!(resp1.hdr.status, DdiStatus::Success);
            assert_ne!(resp1.data.key_id, 0);

            // Side B: derive Secret256 from (priv2, pub1).  Both sides
            // must succeed; the fact that both ECDH operations produce
            // a vault entry is the firmware-side smoke contract — the
            // bit-level equality of the two secrets is exercised by
            // the full `ecdh_256_key_exchange` integration test.
            let resp2 = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id2,
                MborByteArray::new(pub_key1, pub_key1_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret256,
                helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App),
            )
            .unwrap();
            assert_eq!(resp2.hdr.status, DdiStatus::Success);
            assert_ne!(resp2.data.key_id, 0);
            assert_ne!(resp1.data.key_id, resp2.data.key_id);
        },
    );
}

#[test]
fn test_ecdh_key_exchange_unknown_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Borrow only the peer's public key from the helper; the
            // private key we attempt ECDH against is an unknown id.
            let (_, _, _, _, pub_key2, pub_key2_len) = helper_create_ecc_key_pairs(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiEccCurve::P256,
                None,
            );

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let err = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                0xFFFF, /* unknown priv key id */
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret256,
                key_props,
            )
            .expect_err("EcdhKeyExchange must reject an unknown priv_key_id");

            // The exact error code differs across backends — emu's
            // vault returns `KeyNotFound`, the mock returns
            // `InvalidKeyNumber`.
            assert!(
                matches!(
                    err,
                    DdiError::DdiStatus(DdiStatus::KeyNotFound)
                        | DdiError::DdiStatus(DdiStatus::InvalidKeyNumber)
                ),
                "expected KeyNotFound or InvalidKeyNumber, got {:?}",
                err
            );
        },
    );
}

#[test]
fn test_ecdh_key_exchange_curve_mismatch_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Generate a P-256 keypair, then request a Secret384
            // target.  The handler must reject the mismatched curve
            // / target-key-type pair without doing any ECDH work.
            let (priv_key_id1, _pub_key1, _pub_key1_len, _priv_key_id2, pub_key2, pub_key2_len) =
                helper_create_ecc_key_pairs(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    DdiEccCurve::P256,
                    None,
                );

            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::App);
            let err = helper_ecdh_key_exchange(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                priv_key_id1,
                MborByteArray::new(pub_key2, pub_key2_len).expect("failed to create byte array"),
                None,
                DdiKeyType::Secret384, /* mismatched target — priv is P-256 */
                key_props,
            )
            .expect_err("EcdhKeyExchange must reject a curve / target-key-type mismatch");

            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::InvalidKeyType)),
                "expected InvalidKeyType, got {:?}",
                err
            );
        },
    );
}
