// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! HMAC smoke tests.
//!
//! - **Fixed HMAC keys** (both backends): derive an `HmacSha256` /
//!   `384` / `512` key (ECDH → HKDF) and compute a MAC, confirming the
//!   tag length matches the key's hash (32 / 48 / 64 bytes).
//! - **Variable-length HMAC keys** (emu only — the sim has no var-len
//!   HMAC kind): same, deriving `VarHmac256` / `384` / `512`.
//! - **Unknown key** (both backends): a MAC against a non-existent
//!   `key_id` is rejected with `KeyNotFound`.
//! - **Sign permission** (emu only): a `derive`-only HMAC key cannot
//!   generate a MAC — rejected with `InvalidPermissions` (MAC
//!   generation is a PKCS#11 `C_Sign` operation requiring `CKA_SIGN`).

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_codec::MborByteArray;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

/// Compute a MAC over a fixed message with `key_id`.
fn hmac_msg(
    dev: &mut <DdiTest as Ddi>::Dev,
    session_id: u16,
    key_id: u16,
) -> Result<DdiHmacCmdResp, DdiError> {
    helper_hmac(
        dev,
        Some(session_id),
        Some(DdiApiRev { major: 1, minor: 0 }),
        key_id,
        MborByteArray::from_slice(&[0xA5u8; 64]).unwrap(),
    )
}

#[test]
fn test_hmac_fixed_key_sign_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            for (key_type, tag_len) in [
                (DdiKeyType::HmacSha256, 32usize),
                (DdiKeyType::HmacSha384, 48),
                (DdiKeyType::HmacSha512, 64),
            ] {
                let key_id = create_hmac_key(session_id, key_type, dev, Default::default());
                let resp = hmac_msg(dev, session_id, key_id)
                    .unwrap_or_else(|e| panic!("HMAC with {key_type:?} should succeed: {e:?}"));
                assert_eq!(resp.hdr.op, DdiOp::Hmac);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_eq!(resp.data.tag.len(), tag_len, "tag length for {key_type:?}");
            }
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_hmac_var_hmac_key_sign_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            for (key_type, key_len, tag_len) in [
                (DdiKeyType::VarHmac256, 48u8, 32usize),
                (DdiKeyType::VarHmac384, 64, 48),
                (DdiKeyType::VarHmac512, 96, 64),
            ] {
                let key_id = create_hmac_key(session_id, key_type, dev, Some(key_len));
                let resp = hmac_msg(dev, session_id, key_id)
                    .unwrap_or_else(|e| panic!("HMAC with {key_type:?} should succeed: {e:?}"));
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_eq!(resp.data.tag.len(), tag_len, "tag length for {key_type:?}");
            }
        },
    );
}

#[test]
fn test_hmac_unknown_key_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Id 20 is an in-range but unallocated slot (no app keys
            // are created in this test), which both backends report as
            // `KeyNotFound`.
            let err = hmac_msg(dev, session_id, 20)
                .expect_err("MAC against an unknown key must be rejected");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::KeyNotFound)),
                "expected KeyNotFound, got {err:?}"
            );
        },
    );
}

#[cfg(not(feature = "mock"))]
#[test]
fn test_hmac_requires_sign_permission_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Derive a var-len HMAC key with `derive`-only usage, then
            // try to generate a MAC with it.  MAC generation is a
            // PKCS#11 `C_Sign` operation, so a key lacking `CKA_SIGN`
            // must be rejected.
            let (secret_id, _) = create_ecdh_secrets(session_id, dev, DdiKeyType::Secret256);
            let key_props = helper_key_properties(DdiKeyUsage::Derive, DdiKeyAvailability::Session);
            let derived = helper_hkdf_derive(
                dev,
                Some(session_id),
                Some(DdiApiRev { major: 1, minor: 0 }),
                secret_id,
                DdiHashAlgorithm::Sha256,
                None,
                None,
                DdiKeyType::VarHmac256,
                None,
                key_props,
                Some(32),
            )
            .expect("derive-only var-HMAC key should be created");

            let err = hmac_msg(dev, session_id, derived.data.key_id)
                .expect_err("MAC with a derive-only key must be rejected");
            assert!(
                matches!(err, DdiError::DdiStatus(DdiStatus::InvalidPermissions)),
                "expected InvalidPermissions, got {err:?}"
            );
        },
    );
}
