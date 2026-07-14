// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AesGenerateKey smoke tests for the emu backend.
//!
//! - Happy path: generate an AES-128/192/256 encrypt/decrypt key in an
//!   open session and confirm the response carries a non-zero `key_id`
//!   and a populated masked-key envelope (randomized IV).
//! - Without a session: rejected by the host-side dev validator
//!   before the request reaches firmware.

#![cfg(test)]

use azihsm_ddi::*;
use azihsm_ddi_mbor_test_helpers::helper_key_properties;
use azihsm_ddi_mbor_types::*;
use test_with_tracing::test;

use super::common::*;

#[test]
fn test_aes_generate_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, session_id| {
            // Every AES key size must import cleanly and return a
            // populated masked-key envelope.
            for key_size in [
                DdiAesKeySize::Aes128,
                DdiAesKeySize::Aes192,
                DdiAesKeySize::Aes256,
            ] {
                let key_props =
                    helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
                let resp = helper_aes_generate(
                    dev,
                    Some(session_id),
                    Some(DdiApiRev { major: 1, minor: 0 }),
                    key_size,
                    None,
                    key_props,
                )
                .unwrap();

                assert_eq!(resp.hdr.op, DdiOp::AesGenerateKey);
                assert_eq!(resp.hdr.status, DdiStatus::Success);
                assert_ne!(resp.data.key_id, 0, "key_id must be non-zero");
                assert!(
                    resp.data.bulk_key_id.is_none(),
                    "non-bulk AES request must carry bulk_key_id = None"
                );

                // The generated key is returned as a populated masked-key
                // envelope with a randomized IV and the requested attributes.
                assert!(
                    !resp.data.masked_key.as_slice().is_empty(),
                    "masked_key must be populated for {key_size:?}",
                );
                assert!(
                    verify_iv_not_default_from_masked_key(resp.data.masked_key.as_slice())
                        .unwrap_or(false),
                    "masked_key IV must be randomized for {key_size:?}",
                );
                assert!(
                    verify_masked_key_attributes(
                        resp.data.masked_key.as_slice(),
                        MaskedKeyAttributes::ENCRYPT | MaskedKeyAttributes::DECRYPT
                    ),
                    "masked_key attributes must include ENCRYPT|DECRYPT for {key_size:?}",
                );
            }
        },
    );
}

#[test]
fn test_aes_generate_no_session_smoke() {
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, _ddi, _path, _session_id| {
            let key_props =
                helper_key_properties(DdiKeyUsage::EncryptDecrypt, DdiKeyAvailability::App);
            let err = helper_aes_generate(
                dev,
                None,
                Some(DdiApiRev { major: 1, minor: 0 }),
                DdiAesKeySize::Aes128,
                None,
                key_props,
            )
            .expect_err("AesGenerateKey must be rejected without a session");

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
